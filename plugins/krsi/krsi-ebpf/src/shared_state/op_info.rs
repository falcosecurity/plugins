use aya_ebpf::{macros::map, maps::HashMap};

use crate::FileDescriptor;

/// Bind operation shared data.
pub struct BindData {
    pub file_descriptor: FileDescriptor,
}

/// Connect operation shared data.
pub struct ConnectData {
    pub file_descriptor: FileDescriptor,
    pub is_iou: bool,
    pub socktuple_len: u16,
}

/// Linkat operation shared data.
pub struct LinkatData {}

/// Mkdirat operation shared data.
pub struct MkdiratData {}

/// Open operation shared data.
pub struct OpenData {
    pub fd_installed: bool,
}

/// Renameat operation shared data.
pub struct RenameatData {}

/// Symlinkat operation shared data.
pub struct SymlinkatData {}

/// Unlinkat operation shared data.
pub struct UnlinkatData {
    pub is_iou: bool,
    pub flags: Option<i32>,
}

/// Defines the state shared between different programs installed on different hooks for the purpose
/// of extracting information for a given operation. If state sharing is needed, an operation will
/// have its corresponding enum variant.
pub enum OpInfo {
    Bind(BindData),
    Connect(ConnectData),
    Linkat(LinkatData),
    Mkdirat(MkdiratData),
    Open(OpenData),
    Renameat(RenameatData),
    Symlinkat(SymlinkatData),
    Unlinkat(UnlinkatData),
}

#[map]
/// Map containing, for each thread the state shared among different programs cooperating for
/// handling a single operation.
static OP_INFO: HashMap<u32, OpInfo> = HashMap::with_max_entries(32768, 0);

/// Associate the given `info` to the thread corresponding to the given `pid`.
pub fn insert(pid: u32, info: &OpInfo) -> Result<u32, i64> {
    OP_INFO.insert(&pid, info, 0).map(|_| 0)
}

/// Retrieve an immutable borrow to the information associated to the thread corresponding to the
/// given `pid`, if any.
pub unsafe fn get(pid: u32) -> Option<&'static OpInfo> {
    OP_INFO.get(&pid)
}

/// Retrieve a mutable borrow to the information associated to the thread corresponding to the given
/// `pid`, in any.
pub unsafe fn get_mut(pid: u32) -> Option<&'static mut OpInfo> {
    OP_INFO.get_ptr_mut(&pid)?.as_mut()
}

/// Remove the information associated to the thread corresponding to the given `pid`, if any.
pub fn remove(pid: u32) -> Result<u32, i64> {
    OP_INFO.remove(&pid).map(|_| 0)
}
