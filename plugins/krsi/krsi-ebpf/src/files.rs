mod dev;
pub mod extractors;
pub mod getters;

const OVERLAYFS_SUPER_MAGIC: u64 = 0x794c7630;

pub enum Overlay {
    None = 0,
    Upper,
    Lower,
}

impl TryFrom<u16> for Overlay {
    type Error = ();

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            x if x == Overlay::None as u16 => Ok(Overlay::None),
            x if x == Overlay::Upper as u16 => Ok(Overlay::Upper),
            x if x == Overlay::Lower as u16 => Ok(Overlay::Lower),
            _ => Err(()),
        }
    }
}
