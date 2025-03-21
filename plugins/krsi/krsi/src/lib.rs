use aya::programs::KProbe;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};
use aya::maps::RingBuf;
use falco_plugin::async_event::{AsyncEvent, AsyncEventPlugin, AsyncHandler};
use falco_plugin::event::events::{Event, EventMetadata};
use falco_plugin::tables::import::{Entry, Table, TableMetadata};
use falco_plugin::anyhow::Error;
use falco_plugin::base::{Json, Plugin};
use falco_plugin::event::events::types::{EventType, PPME_SYSCALL_CLONE_20_X};
use falco_plugin::extract::{field, EventInput, ExtractFieldInfo, ExtractPlugin, ExtractRequest};
use falco_plugin::schemars::JsonSchema;
use falco_plugin::parse::{ParseInput, ParsePlugin};
use serde::Deserialize;
use falco_plugin::{async_event_plugin, extract_plugin, parse_plugin, plugin};
use falco_plugin::tables::TablesInput;
use std::ffi::{CStr, CString};
use hashlru::Cache;
use falco_plugin::event::fields::types::PT_PID;
use std::sync::atomic::Ordering;
use aya::EbpfLoader;
#[rustfmt::skip]
use log::debug;

mod krsi_event;
use crate::krsi_event::{KrsiEvent, KrsiEventContent};

#[derive(TableMetadata)]
#[entry_type(ImportedThread)]
struct ImportedThreadMetadata {
}

type ImportedThread = Entry<Arc<ImportedThreadMetadata>>;
type ImportedThreadTable = Table<i64, ImportedThread>;


pub struct KrsiPlugin {
    ebpf: aya::Ebpf,
    threads: ImportedThreadTable,
    async_handler: Option<Arc<AsyncHandler>>,
    missing_events: Cache<i64, Vec<krsi_event::KrsiEvent>>,

    bt_thread: Option<JoinHandle<Result<(), Error>>>,
    bt_stop: Arc<AtomicBool>
}

#[derive(JsonSchema, Deserialize)]
#[schemars(crate = "falco_plugin::schemars")]
#[serde(crate = "falco_plugin::serde")]
pub struct Config {
}

/// Plugin metadata
impl Plugin for KrsiPlugin {
    const NAME: &'static CStr = c"krsi";
    const PLUGIN_VERSION: &'static CStr = c"0.0.1";
    const DESCRIPTION: &'static CStr = c"Falco support for Kernel Runtime Security Instrumentation";
    const CONTACT: &'static CStr = c"https://falco.org";
    type ConfigType = Json<Config>;

    fn new(input: Option<&TablesInput>, Json(_config): Self::ConfigType) -> Result<Self, Error> {
        let input = input.ok_or_else(|| anyhow::anyhow!("did not get table input"))?;
        let threads: ImportedThreadTable = input.get_table(c"threads")?;

        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };

        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {}", ret);
        }

        // This will include your eBPF object file as raw bytes at compile-time and load it at
        // runtime. This approach is recommended for most real-world use cases. If you would
        // like to specify the eBPF program at runtime rather than at compile-time, you can
        // reach for `Bpf::load_file` instead.
        let cpus = num_cpus::get();
        let ebpf = EbpfLoader::new()
            .set_max_entries("AUXILIARY_MAPS", cpus as u32)
            .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/krsi"
        )))?;

        Ok(Self {
            ebpf,
            threads,
            async_handler: None,
            missing_events: Cache::new(1024),

            bt_thread: None,
            bt_stop: Arc::new(AtomicBool::new(false)),
        })
    }

    fn set_config(&mut self, _config: Self::ConfigType) -> Result<(), Error> {
        Ok(())
    }
}

// this parses an event coming from the ringbuffer

fn emit_async_event(handler: &AsyncHandler, event: &KrsiEvent, event_name: &CStr) -> Result<(), Error> {
    let serialized = bincode::serde::encode_to_vec(&event, bincode::config::legacy()).unwrap();
    let ts = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos() as u64;
    let tid = event.tid as i64;

    let event = AsyncEvent {
        plugin_id: None,
        name: Some(event_name),
        data: Some(&serialized),
    };
    let metadata = EventMetadata {
        ts,
        tid,
    };
    let event = Event {
        metadata,
        params: event,
    };

    handler.emit(event)?;

    Ok(())
}

/// Event Parsing Capability
impl ParsePlugin for KrsiPlugin {
    const EVENT_TYPES: &'static [EventType] = &[EventType::ASYNCEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &["syscall"];
  
    fn parse_event(&mut self, event: &EventInput, parse_input: &ParseInput) -> Result<(), Error> {
        let r = &parse_input.reader;
        // let w = &parse_input.writer;
        let event = event.event()?;

        if let Ok(mut event) = event.load::<AsyncEvent>() {
            if event.params.name != Some(c"krsi") {
                return Ok(());
            }

            let Some(buf) = event.params.data else {
                println!("missing event data");
                anyhow::bail!("Missing event data");
            };

            let ev: KrsiEvent = bincode::serde::decode_from_slice(buf, bincode::config::legacy())?.0;
            let tid = ev.tid as i64;

            if self.threads.get_entry(r, &tid).is_ok() {
                match ev.content {
                    KrsiEventContent::Open { fd: _, name: _, flags: _, mode: _, dev: _, ino: _ } => {
                        event.params.name = Some(c"krsi_open");
                        if let Some(handler) = self.async_handler.as_ref() {
                            handler.emit(event)?;
                        }
                    }
                }
            } else {
                let tid = ev.tid as i64;
                let entry = if let Some(entry) = self.missing_events.get_mut(&tid) {
                    entry
                } else {
                    self.missing_events.insert(tid, Vec::new());
                    self.missing_events.get_mut(&tid).unwrap()
                };
                
                entry.push(ev);
            }
        } else if let Ok(event) = event.load::<PPME_SYSCALL_CLONE_20_X>() {
            let Some(PT_PID(child_tid)) = event.params.res else {
                return Ok(());
            };

            let Some(missing_events) = self.missing_events.remove(&child_tid) else {
                return Ok(());
            };

            let Some(handler) = self.async_handler.as_ref() else {
                return Ok(());
            };

            for missing_event in missing_events {
                emit_async_event(handler, &missing_event, c"krsi")?;
            }
        }

        Ok(())
    }
}

const RETRY_INTERVAL_START: Duration = Duration::from_nanos(1);
const RETRY_INTERVAL_MAX: Duration = Duration::from_millis(10);

impl AsyncEventPlugin for KrsiPlugin {
    const ASYNC_EVENTS: &'static [&'static str] = &["krsi_open", "krsi"];
    const EVENT_SOURCES: &'static [&'static str] = &["syscall"];

    fn start_async(&mut self, handler: falco_plugin::async_event::AsyncHandler) -> Result<(), anyhow::Error> {
        // stop the thread if it was already running
        if self.bt_thread.is_some() {
            self.stop_async()?;
        }
 
        let fd_install_prog: &mut KProbe = self.ebpf.program_mut("fd_install").unwrap().try_into()?;
        fd_install_prog.load()?;
        fd_install_prog.attach("fd_install", 0)?;
    
        let sec_file_open_prog: &mut KProbe =
            self.ebpf.program_mut("security_file_open").unwrap().try_into()?;
        sec_file_open_prog.load()?;
        sec_file_open_prog.attach("security_file_open", 0)?;

        let mut ring_buf = RingBuf::try_from(self.ebpf.take_map("EVENTS").unwrap()).unwrap();

        let handler = Arc::new(handler);
        self.async_handler = Some(handler.clone());

        self.bt_stop.store(false, Ordering::Relaxed);
        let bt_stop = self.bt_stop.clone();
        
        self.bt_thread = Some(std::thread::spawn(move || {
            let mut retry_interval = RETRY_INTERVAL_START;
            while !bt_stop.load(Ordering::Relaxed) {
                if let Some(item) = ring_buf.next() {
                    let buf = &*item;
                    if let Ok(event) = krsi_event::parse_ringbuf_event(buf) {
                        emit_async_event(handler.as_ref(), &event, c"krsi")?;
                        retry_interval = RETRY_INTERVAL_START;
                    }
                } else {
                    std::thread::sleep(retry_interval);
                    retry_interval = std::cmp::min(retry_interval + retry_interval / 2, RETRY_INTERVAL_MAX);
                }
            }
            Ok(())
        }));
        Ok(())
    }

    fn stop_async(&mut self) -> Result<(), anyhow::Error> {
        self.bt_stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.bt_thread.take() {
            thread.join().unwrap()?;
        }
        Ok(())
    }
}

impl KrsiPlugin {
    fn extract_filename(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let event = req.event.event()?;
        let event = event.load::<AsyncEvent>()?;
        if event.params.name != Some(c"krsi_open") {
            return Ok(c"".to_owned());
        }

        let Some(buf) = event.params.data else {
            anyhow::bail!("Missing event data");
        };

        let ev: KrsiEvent = bincode::serde::decode_from_slice(buf, bincode::config::legacy())?.0;
        let KrsiEventContent::Open { fd: _, name, flags: _, mode: _, dev: _, ino: _ } = ev.content;
        Ok(CString::new(name).unwrap())
    }
}

impl ExtractPlugin for KrsiPlugin {
    const EVENT_TYPES: &'static [EventType] = &[EventType::ASYNCEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &["syscall"];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
        field("krsi.filename", &Self::extract_filename),
        // field("fd.name", &Self::extract_fd_name),
    ];
}

plugin!(KrsiPlugin);
async_event_plugin!(KrsiPlugin);
parse_plugin!(KrsiPlugin);
extract_plugin!(KrsiPlugin);
