// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

use std::{
    ffi::{CStr, CString},
    net::IpAddr,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::JoinHandle,
    time::{Duration, SystemTime},
};

use falco_plugin::{
    anyhow::Error,
    async_event::{AsyncEvent, AsyncEventPlugin, AsyncHandler},
    async_event_plugin,
    base::{Json, Plugin},
    event::{
        events::{
            types::{EventType, PPME_SYSCALL_CLONE_20_X},
            Event, EventMetadata,
        },
        fields::types::PT_PID,
    },
    extract::{field, EventInput, ExtractFieldInfo, ExtractPlugin, ExtractRequest},
    extract_plugin,
    parse::{ParseInput, ParsePlugin},
    parse_plugin, plugin,
    schemars::JsonSchema,
    tables::{
        import::{Entry, Field, Table, TableMetadata},
        LazyTableReader, LazyTableWriter, TablesInput,
    },
};
use hashlru::Cache;
use krsi_common::flags::{FeatureFlags, OpFlags};
use serde::Deserialize;

mod ebpf;
mod krsi_event;

use crate::krsi_event::{KrsiEvent, KrsiEventContent};

#[derive(TableMetadata)]
#[entry_type(ImportedFileDescriptor)]
struct ImportedFileDescriptorMetadata {
    name: Field<CStr, ImportedFileDescriptor>,
    fd: Field<i64, ImportedFileDescriptor>,
    dev: Field<u32, ImportedFileDescriptor>,
    ino: Field<u64, ImportedFileDescriptor>,
    flags: Field<u32, ImportedFileDescriptor>,
}

type ImportedFileDescriptor = Entry<Arc<ImportedFileDescriptorMetadata>>;
type ImportedFileDescriptorTable = Table<i64, ImportedFileDescriptor>;

#[derive(TableMetadata)]
#[entry_type(ImportedThread)]
struct ImportedThreadMetadata {
    tid: Field<i64, ImportedThread>,
    pid: Field<i64, ImportedThread>,
    ptid: Field<i64, ImportedThread>,
    comm: Field<CStr, ImportedThread>,
    file_descriptors: Field<ImportedFileDescriptorTable, ImportedThread>,
    reaper_tid: Field<i64, ImportedThread>,
    sid: Field<i64, ImportedThread>,
    exe: Field<CStr, ImportedThread>,
    exe_path: Field<CStr, ImportedThread>,
    // exe_writable: Field<bool, ImportedThread>,
    // exe_upper_layer: Field<bool, ImportedThread>,
    // exe_lower_layer: Field<bool, ImportedThread>,
    // exe_from_memfd: Field<bool, ImportedThread>,
    flags: Field<u32, ImportedThread>,
    fd_limit: Field<i64, ImportedThread>,
    uid: Field<u32, ImportedThread>,
    gid: Field<u32, ImportedThread>,
    loginuid: Field<u32, ImportedThread>,
    exe_ino: Field<u64, ImportedThread>,
    exe_ino_ctime: Field<u64, ImportedThread>,
    exe_ino_mtime: Field<u64, ImportedThread>,
    vtid: Field<i64, ImportedThread>,
    vpid: Field<i64, ImportedThread>,
    vpgid: Field<i64, ImportedThread>,
    pgid: Field<i64, ImportedThread>,
    pidns_init_start_ts: Field<u64, ImportedThread>,
    root: Field<CStr, ImportedThread>,
    tty: Field<u32, ImportedThread>,
}

type ImportedThread = Entry<Arc<ImportedThreadMetadata>>;
type ImportedThreadTable = Table<i64, ImportedThread>;

pub struct KrsiPlugin {
    ebpf: ebpf::Ebpf,
    threads: ImportedThreadTable,
    async_handler: Option<Arc<AsyncHandler>>,
    missing_events: Cache<i64, Vec<krsi_event::KrsiEvent>>,

    bt_thread: Option<JoinHandle<Result<(), Error>>>,
    bt_stop: Arc<AtomicBool>,
}

#[derive(JsonSchema, Deserialize)]
#[schemars(crate = "falco_plugin::schemars")]
#[serde(crate = "falco_plugin::serde")]
pub struct Config {
    /// io_uring operations enabled
    #[serde(default)]
    io_uring: bool,

    /// syscall operations enabled
    #[serde(default)]
    syscalls: bool,
}
/// Plugin metadata
impl Plugin for KrsiPlugin {
    const NAME: &'static CStr = c"krsi";
    const PLUGIN_VERSION: &'static CStr = c"0.0.1";
    const DESCRIPTION: &'static CStr = c"Falco support for Kernel Runtime Security Instrumentation";
    const CONTACT: &'static CStr = c"https://falco.org";
    type ConfigType = Json<Config>;

    fn new(input: Option<&TablesInput>, Json(config): Self::ConfigType) -> Result<Self, Error> {
        let input = input.ok_or_else(|| anyhow::anyhow!("did not get table input"))?;
        let threads: ImportedThreadTable = input.get_table(c"threads")?;

        let mut feature_flags = FeatureFlags::NONE;
        if config.io_uring {
            feature_flags |= FeatureFlags::IO_URING;
        }
        if config.syscalls {
            feature_flags |= FeatureFlags::SYSCALLS;
        }
        let op_flags = OpFlags::all();

        let ebpf = ebpf::Ebpf::try_new(false, feature_flags, op_flags)?;

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

fn emit_async_event(
    handler: &AsyncHandler,
    event: &KrsiEvent,
    event_name: &CStr,
) -> Result<(), Error> {
    let serialized = bincode::serde::encode_to_vec(&event, bincode::config::legacy()).unwrap();
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let tid = event.tid;

    let event = AsyncEvent {
        plugin_id: None,
        name: Some(event_name),
        data: Some(&serialized),
    };
    let metadata = EventMetadata {
        ts,
        tid: tid as i64,
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
        let w = &parse_input.writer;
        let event = event.event()?;

        if let Ok(mut event) = event.load::<AsyncEvent>() {
            if event.params.name != Some(c"krsi") {
                return Ok(());
            }

            let Some(buf) = event.params.data else {
                println!("missing event data");
                anyhow::bail!("Missing event data");
            };

            let ev: KrsiEvent =
                bincode::serde::decode_from_slice(buf, bincode::config::legacy())?.0;
            let tid = ev.tid as i64;
            let pid = ev.pid as i64;

            let mut thread_exists = self.threads.get_entry(r, &tid).is_ok();

            if !thread_exists && self.threads.get_entry(r, &pid).is_ok() {
                // PID exists, but TID does not.
                // This can happen because the kernel might have created an async thread for that
                // specific operation; we can still create a new thread and emit the event
                self.create_child_thread(r, w, tid, pid)?;
                thread_exists = true;
            }

            if thread_exists {
                // There is a thread, update the fd table and create the event
                match ev.content {
                    KrsiEventContent::Open {
                        fd,
                        file_index: _,
                        name,
                        flags,
                        mode: _,
                        dev,
                        ino,
                        iou_ret: _,
                    } => {
                        if let Some(fd) = fd {
                            let thread = self.threads.get_entry(r, &tid)?;
                            let fds = thread.get_file_descriptors(r)?;
                            let fd_entry = if let Ok(existing_fd) = fds.get_entry(r, &fd) {
                                existing_fd
                            } else {
                                let new_fd = fds.create_entry(w)?;
                                fds.insert(r, w, &fd, new_fd)?;
                                fds.get_entry(r, &fd)?
                            };

                            fd_entry.set_fd(w, &fd)?;
                            if let Some(name) = name {
                                let c_name = CString::from_str(&name)?;
                                fd_entry.set_name(w, &c_name)?;
                            }

                            if let Some(dev) = dev {
                                fd_entry.set_dev(w, &dev)?;
                            }

                            if let Some(ino) = ino {
                                fd_entry.set_ino(w, &ino)?;
                            }

                            if let Some(flags) = flags {
                                // keep flags added by the syscall exit probe if present
                                let mask: u32 = !(krsi_common::scap::PPM_O_F_CREATED - 1);
                                let added_flags: u32 = flags & mask;
                                let flags = flags | added_flags;
                                fd_entry.set_flags(w, &flags)?;
                            }
                        }

                        event.params.name = Some(c"krsi_open");
                        if let Some(handler) = self.async_handler.as_ref() {
                            handler.emit(event)?;
                        }
                    }
                    KrsiEventContent::Connect { fd, .. } => {
                        if let Some(fd) = fd {
                            let thread = self.threads.get_entry(r, &tid)?;
                            let fds = thread.get_file_descriptors(r)?;
                            let fd_entry = if let Ok(existing_fd) = fds.get_entry(r, &fd) {
                                existing_fd
                            } else {
                                let new_fd = fds.create_entry(w)?;
                                fds.insert(r, w, &fd, new_fd)?;
                                fds.get_entry(r, &fd)?
                            };
                            fd_entry.set_fd(w, &fd)?;
                        }

                        event.params.name = Some(c"krsi_connect");
                        if let Some(handler) = self.async_handler.as_ref() {
                            handler.emit(event)?;
                        }
                    }
                    KrsiEventContent::Socket { .. } => {
                        // TODO this
                        event.params.name = Some(c"krsi_socket");
                        if let Some(handler) = self.async_handler.as_ref() {
                            handler.emit(event)?;
                        }
                    }
                    KrsiEventContent::Symlinkat { .. } => {
                        event.params.name = Some(c"krsi_symlinkat");
                        if let Some(handler) = self.async_handler.as_ref() {
                            handler.emit(event)?;
                        }
                    }
                    KrsiEventContent::Linkat { .. } => {
                        event.params.name = Some(c"krsi_linkat");
                        if let Some(handler) = self.async_handler.as_ref() {
                            handler.emit(event)?;
                        }
                    }
                    KrsiEventContent::Unlinkat { .. } => {
                        event.params.name = Some(c"krsi_unlinkat");
                        if let Some(handler) = self.async_handler.as_ref() {
                            handler.emit(event)?;
                        }
                    }
                    KrsiEventContent::Mkdirat { .. } => {
                        event.params.name = Some(c"krsi_mkdirat");
                        if let Some(handler) = self.async_handler.as_ref() {
                            handler.emit(event)?;
                        }
                    }
                }
            } else {
                // No thread available, wait for it to be created
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
    const ASYNC_EVENTS: &'static [&'static str] = &[
        "krsi_open",
        "krsi_connect",
        "krsi_socket",
        "krsi_symlinkat",
        "krsi_linkat",
        "krsi_unlinkat",
        "krsi_mkdirat",
        "krsi",
    ];
    const EVENT_SOURCES: &'static [&'static str] = &["syscall"];

    fn start_async(
        &mut self,
        handler: falco_plugin::async_event::AsyncHandler,
    ) -> Result<(), anyhow::Error> {
        // stop the thread if it was already running
        if self.bt_thread.is_some() {
            self.stop_async()?;
        }

        self.ebpf.load_and_attach_programs()?;
        let mut ring_buf = self.ebpf.ring_buffer()?;

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
                    retry_interval =
                        std::cmp::min(retry_interval + retry_interval / 2, RETRY_INTERVAL_MAX);
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
    fn create_child_thread(
        &mut self,
        r: &LazyTableReader<'_>,
        w: &LazyTableWriter<'_>,
        tid: i64,
        pid: i64,
    ) -> Result<(), Error> {
        let process = self.threads.get_entry(r, &pid)?;
        let entry = self.threads.create_entry(w)?;
        entry.set_tid(w, &tid)?;
        entry.set_pid(w, &pid)?;
        entry.set_ptid(w, &pid)?;

        let comm = process.get_comm(r)?;
        entry.set_comm(w, comm)?;

        let reaper_tid = process.get_reaper_tid(r)?;
        entry.set_reaper_tid(w, &reaper_tid)?;

        let sid = process.get_sid(r)?;
        entry.set_sid(w, &sid)?;

        let exe = process.get_exe(r)?;
        entry.set_exe(w, &exe)?;

        let exe_path = process.get_exe_path(r)?;
        entry.set_exe_path(w, &exe_path)?;

        let flags = process.get_flags(r)?;
        entry.set_flags(w, &flags)?;

        let fd_limit = process.get_fd_limit(r)?;
        entry.set_fd_limit(w, &fd_limit)?;

        let uid = process.get_uid(r)?;
        entry.set_uid(w, &uid)?;

        let gid = process.get_gid(r)?;
        entry.set_gid(w, &gid)?;

        let loginuid = process.get_loginuid(r)?;
        entry.set_loginuid(w, &loginuid)?;

        let exe_ino = process.get_exe_ino(r)?;
        entry.set_exe_ino(w, &exe_ino)?;

        let exe_ino_ctime = process.get_exe_ino_ctime(r)?;
        entry.set_exe_ino_ctime(w, &exe_ino_ctime)?;

        let exe_ino_mtime = process.get_exe_ino_mtime(r)?;
        entry.set_exe_ino_mtime(w, &exe_ino_mtime)?;

        let vtid = process.get_vtid(r)?;
        entry.set_vtid(w, &vtid)?;

        let vpid = process.get_vpid(r)?;
        entry.set_vpid(w, &vpid)?;

        let vpgid = process.get_vpgid(r)?;
        entry.set_vpgid(w, &vpgid)?;

        let pgid = process.get_pgid(r)?;
        entry.set_pgid(w, &pgid)?;

        let pidns_init_start_ts = process.get_pidns_init_start_ts(r)?;
        entry.set_pidns_init_start_ts(w, &pidns_init_start_ts)?;

        let root = process.get_root(r)?;
        entry.set_root(w, &root)?;

        let tty = process.get_tty(r)?;
        entry.set_tty(w, &tty)?;

        self.threads.insert(r, w, &tid, entry)?;
        Ok(())
    }

    fn parse_krsi_event<'a>(
        &self,
        context: &'a mut Option<KrsiEvent>,
        event: &EventInput,
    ) -> Result<&'a KrsiEvent, Error> {
        match context {
            Some(parsed_event) => Ok(parsed_event),
            None => {
                let event = event.event()?;
                let event = event.load::<AsyncEvent>()?;

                let Some(buf) = event.params.data else {
                    anyhow::bail!("Missing event data");
                };

                let parsed_event: KrsiEvent =
                    bincode::serde::decode_from_slice(buf, bincode::config::legacy())?.0;
                *context = Some(parsed_event);

                Ok(context.as_ref().unwrap())
            }
        }
    }

    fn extract_fd_name(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(name) = ev.content.name() {
            return Ok(CString::new(name).unwrap());
        } else {
            anyhow::bail!("No name field");
        }
    }

    fn extract_fd(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(fd) = ev.content.fd() {
            return Ok(fd as u64);
        } else {
            anyhow::bail!("No fd field");
        }
    }

    fn extract_file_index(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(file_index) = ev.content.file_index() {
            return Ok(file_index as u64);
        } else {
            anyhow::bail!("No file_index field");
        }
    }

    fn extract_flags(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(flags) = ev.content.flags() {
            return Ok(flags as u64);
        } else {
            anyhow::bail!("No flags field");
        }
    }

    fn extract_mode(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(mode) = ev.content.mode() {
            return Ok(mode as u64);
        } else {
            anyhow::bail!("No mode field");
        }
    }

    fn extract_dev(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(dev) = ev.content.dev() {
            return Ok(dev as u64);
        } else {
            anyhow::bail!("No dev field");
        }
    }

    fn extract_ino(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(ino) = ev.content.ino() {
            return Ok(ino as u64);
        } else {
            anyhow::bail!("No ino field");
        }
    }

    fn extract_domain(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(domain) = ev.content.domain() {
            return Ok(domain as u64);
        } else {
            anyhow::bail!("No domain field");
        }
    }

    // res
    fn extract_res(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(res) = ev.content.res() {
            return Ok(res as u64);
        } else {
            anyhow::bail!("No res field");
        }
    }

    fn extract_linkdirfd(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(linkdirfd) = ev.content.linkdirfd() {
            return Ok(linkdirfd as u64);
        } else {
            anyhow::bail!("No dirfd field");
        }
    }

    fn extract_olddirfd(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(olddirfd) = ev.content.olddirfd() {
            return Ok(olddirfd as u64);
        } else {
            anyhow::bail!("No olddirfd field");
        }
    }

    fn extract_newdirfd(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(newdirfd) = ev.content.newdirfd() {
            return Ok(newdirfd as u64);
        } else {
            anyhow::bail!("No newdirfd field");
        }
    }

    fn extract_dirfd(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(dirfd) = ev.content.dirfd() {
            return Ok(dirfd as u64);
        } else {
            anyhow::bail!("No dirfd field");
        }
    }

    fn extract_linkpath(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(linkpath) = ev.content.linkpath() {
            return Ok(CString::new(linkpath).unwrap());
        } else {
            anyhow::bail!("No linkpath field");
        }
    }

    fn extract_oldpath(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(oldpath) = ev.content.oldpath() {
            return Ok(CString::new(oldpath).unwrap());
        } else {
            anyhow::bail!("No oldpath field");
        }
    }

    fn extract_newpath(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(newpath) = ev.content.newpath() {
            return Ok(CString::new(newpath).unwrap());
        } else {
            anyhow::bail!("No newpath field");
        }
    }

    fn extract_path(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(path) = ev.content.path() {
            return Ok(CString::new(path).unwrap());
        } else {
            anyhow::bail!("No path field");
        }
    }

    fn extract_target(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(target) = ev.content.target() {
            return Ok(CString::new(target).unwrap());
        } else {
            anyhow::bail!("No target field");
        }
    }

    fn extract_type(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(type_) = ev.content.type_() {
            return Ok(type_ as u64);
        } else {
            anyhow::bail!("No type field");
        }
    }

    fn extract_iou_ret(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(iou_ret) = ev.content.iou_ret() {
            return Ok(iou_ret as u64);
        } else {
            anyhow::bail!("No iou_ret field");
        }
    }

    fn extract_cport(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(cport) = ev.content.client_port() {
            return Ok(cport as u64);
        } else {
            anyhow::bail!("No cport field");
        }
    }

    fn extract_sport(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(sport) = ev.content.server_port() {
            return Ok(sport as u64);
        } else {
            anyhow::bail!("No sport field");
        }
    }

    fn extract_cip(&mut self, req: ExtractRequest<Self>) -> Result<IpAddr, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(cip) = ev.content.client_addr() {
            return Ok(cip);
        } else {
            anyhow::bail!("No cip field");
        }
    }

    fn extract_sip(&mut self, req: ExtractRequest<Self>) -> Result<IpAddr, Error> {
        let ev: &KrsiEvent = self.parse_krsi_event(req.context, req.event)?;
        if let Some(sip) = ev.content.server_addr() {
            return Ok(sip);
        } else {
            anyhow::bail!("No sip field");
        }
    }
}

impl ExtractPlugin for KrsiPlugin {
    const EVENT_TYPES: &'static [EventType] = &[EventType::ASYNCEVENT_E];
    const EVENT_SOURCES: &'static [&'static str] = &["syscall"];
    type ExtractContext = Option<KrsiEvent>;
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
        field("krsi.name", &Self::extract_fd_name),
        field("krsi.fd", &Self::extract_fd),
        field("krsi.file_index", &Self::extract_file_index),
        field("krsi.flags", &Self::extract_flags),
        field("krsi.mode", &Self::extract_mode),
        field("krsi.dev", &Self::extract_dev),
        field("krsi.ino", &Self::extract_ino),
        field("krsi.domain", &Self::extract_domain),
        field("krsi.type", &Self::extract_type),
        field("krsi.iou_ret", &Self::extract_iou_ret),
        field("krsi.res", &Self::extract_res),
        field("krsi.target", &Self::extract_target),
        field("krsi.linkdirfd", &Self::extract_linkdirfd),
        field("krsi.olddirfd", &Self::extract_olddirfd),
        field("krsi.newdirfd", &Self::extract_newdirfd),
        field("krsi.dirfd", &Self::extract_dirfd),
        field("krsi.linkpath", &Self::extract_linkpath),
        field("krsi.path", &Self::extract_path),
        field("krsi.oldpath", &Self::extract_oldpath),
        field("krsi.newpath", &Self::extract_newpath),
        field("krsi.cip", &Self::extract_cip),
        field("krsi.sip", &Self::extract_sip),
        field("krsi.cport", &Self::extract_cport),
        field("krsi.sport", &Self::extract_sport),
    ];
}

plugin!(KrsiPlugin);
async_event_plugin!(KrsiPlugin);
parse_plugin!(KrsiPlugin);
extract_plugin!(KrsiPlugin);
