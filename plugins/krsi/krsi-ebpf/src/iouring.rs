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
