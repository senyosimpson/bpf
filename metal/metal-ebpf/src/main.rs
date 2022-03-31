#![no_std]
#![no_main]

mod bindings;
mod util;

use aya_bpf::bindings::xdp_action;
use aya_bpf::macros::{xdp, map};
use aya_bpf::programs::XdpContext;
use aya_bpf::maps::PerfEventArray;
use memoffset::offset_of;

use metal_common::PacketLog;

// Copied values from libc
const ETH_P_IP: i32 = 0x0800;
const ETH_HDR_LEN: i32 = 14;


#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketLog> = PerfEventArray::with_max_entries(1024, 0);

#[xdp(name="metal")]
pub fn metal(ctx: XdpContext) -> u32 {
    match unsafe { try_metal(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn try_metal(ctx: XdpContext) -> Result<u32, ()> {
    let h_proto = u16::from_be(*util::ptr_at(&ctx, offset_of!(bindings::ethhdr, h_proto))?);
    if h_proto != ETH_P_IP as u16 {
        return Ok(xdp_action::XDP_PASS)
    }

    let source = u32::from_be(*util::ptr_at(&ctx, ETH_HDR_LEN as usize + offset_of!(bindings::iphdr, saddr))?);

    let entry = PacketLog {
        ipv4: source,
        action: xdp_action::XDP_PASS
    };

    EVENTS.output(&ctx, &entry, 0);

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
