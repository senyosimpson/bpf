#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketInfo {
    pub protocol: u8,
    pub src_addr: u32,
    pub dst_addr: u32
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketInfo {}