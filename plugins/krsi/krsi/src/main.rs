use aya::maps::RingBuf;
use aya::programs::KProbe;
use aya_log::EbpfLogger;
use krsi_common::{EventHeader, EventType};
use log::warn;
use std::convert::TryFrom;
use libc::user;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/krsi"
    )))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    let fd_install_prog: &mut KProbe = bpf.program_mut("fd_install").unwrap().try_into()?;
    fd_install_prog.load()?;
    fd_install_prog.attach("fd_install", 0)?;

    let sec_file_open_prog: &mut KProbe =
        bpf.program_mut("security_file_open").unwrap().try_into()?;
    sec_file_open_prog.load()?;
    sec_file_open_prog.attach("security_file_open", 0)?;

    let mut ring_buf = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;

    loop {
        if let Some(item) = ring_buf.next() {
            let buf = &*item;
            let mut ptr = buf.as_ptr();
            let ev = unsafe { read_and_move::<EventHeader>(&mut ptr) };
            println!("{ev:?}");
            let mut name_len = 0;
            print!("\t");
            for i in 0..ev.nparams {
                let len = unsafe { read_and_move::<u16>(&mut ptr) };
                if i == 1 {
                    name_len = len;
                }
                print!("len({i})={len} ");
            }
            match ev.evt_type.try_into() {
                Ok(EventType::FdInstall) => {
                    let fd = unsafe { read_and_move::<i64>(&mut ptr) };
                    let name = unsafe{ read_str_and_move(&mut ptr, name_len as usize) };
                    let flags = unsafe { read_and_move::<u32>(&mut ptr) };
                    let mode = unsafe { read_and_move::<u32>(&mut ptr) };
                    let dev = unsafe { read_and_move::<u32>(&mut ptr) };
                    let ino = unsafe { read_and_move::<u64>(&mut ptr) };
                    println!("\n\tfd={fd}, name={name} flags={flags}, mode={mode}, dev={dev}, ino={ino}");
                }
                _ => {}
            }
            // let ev: EventHeader = unsafe { core::ptr::read_unaligned(ptr as *const EventHeader) };
            // events_num += 1;
            // info!("event {events_num}, len {}", item.len());
            // println!("Received item {:?}", item);
            // info!("item: {:?}", &*item);
        }
    }

    //
    // info!("Waiting for Ctrl-C...");
    // signal::ctrl_c().await?;
    // info!("Exiting...");
    //
    // Ok(())
}

unsafe fn read_and_move<T>(ptr: &mut *const u8) -> T {
    let v = (*ptr).cast::<T>().read_unaligned();
    *ptr = (*ptr).byte_add(size_of::<T>());
    v
}

unsafe fn read_str_and_move(ptr: &mut *const u8, len: usize) -> &'static str {
    let s = unsafe {std::str::from_utf8_unchecked(std::slice::from_raw_parts(*ptr, len))};
    *ptr = (*ptr).byte_add(len);
    s
}