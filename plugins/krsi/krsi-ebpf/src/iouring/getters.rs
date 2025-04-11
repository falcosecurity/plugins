use aya_ebpf::cty::c_int;

use crate::{defs, iouring::extractors, vmlinux, FileDescriptor};

/// Returns `Some(req->cqe.res)` if `iou_ret` is `IOU_OK`; otherwise, returns `None`.
pub fn io_kiocb_cqe_res(
    req: *const vmlinux::io_kiocb,
    iou_ret: c_int,
) -> Result<Option<c_int>, i64> {
    if iou_ret != defs::IOU_OK {
        return Ok(None);
    }
    let cqe_res = extractors::io_kiocb_cqe_res(req)?;
    Ok(Some(cqe_res))
}

/// Returns the file descriptor leveraging the information extracted from `req->flags` and
/// `req->cqe.fd`.
pub fn io_kiocb_cqe_file_descriptor(req: *const vmlinux::io_kiocb) -> Result<FileDescriptor, i64> {
    let flags = extractors::io_kiocb_flags(req)?;
    let fd = extractors::io_kiocb_cqe_fd(req)?;
    const REQ_F_FIXED_FILE: u32 = 1;
    Ok(if flags & REQ_F_FIXED_FILE == 0 {
        FileDescriptor::Fd(fd)
    } else {
        FileDescriptor::FileIndex(fd)
    })
}
