use aya_ebpf::cty::c_int;
use krsi_ebpf_core::IoKiocb;

use crate::{defs, FileDescriptor};

/// Returns `Some(req->cqe.res)` if `iou_ret` is `IOU_OK`; otherwise, returns `None`.
pub fn io_kiocb_cqe_res(req: &IoKiocb, iou_ret: i64) -> Result<Option<c_int>, i64> {
    if iou_ret != defs::IOU_OK {
        return Ok(None);
    }
    let cqe_res = req.cqe().res()?;
    Ok(Some(cqe_res))
}

/// Returns the file descriptor leveraging the information extracted from `req->flags` and
/// `req->cqe.fd`.
pub fn io_kiocb_cqe_file_descriptor(req: &IoKiocb) -> Result<FileDescriptor, i64> {
    let flags = req.flags()?;
    let fd = req.cqe().fd()?;
    const REQ_F_FIXED_FILE: u64 = 1;
    Ok(if flags & REQ_F_FIXED_FILE == 0 {
        FileDescriptor::Fd(fd)
    } else {
        FileDescriptor::FileIndex(fd)
    })
}
