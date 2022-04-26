#![no_std]
#![no_main]

mod bindings;

use aya_bpf::bindings as aya_bindings;
use aya_bpf::macros::{classifier, map};
use aya_bpf::maps::PerfEventArray;
use aya_bpf::programs::SkBuffContext;

use memoffset::offset_of;

use skeng_common::PacketInfo;

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketInfo> = PerfEventArray::with_max_entries(1024, 0);

struct Protocol(u8);
struct SourceAddr(u32);
struct DestinationAddr(u32);


#[classifier(name = "skeng")]
pub fn skeng(ctx: SkBuffContext) -> i32 {
    match unsafe { try_skeng(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_skeng(ctx: SkBuffContext) -> Result<i32, i32> {
    let res = ctx.load::<Protocol>(offset_of!(bindings::iphdr, protocol));
    let protocol = match res {
        Ok(protocol) => protocol.0,
        Err(e) => return Err(e as i32),
    };

    let src_addr = match ctx.load::<SourceAddr>(offset_of!(bindings::iphdr, saddr)) {
        Ok(addr) => addr.0,
        Err(e) => return Err(e as i32),
    };

    let dst_addr = match ctx.load::<DestinationAddr>(offset_of!(bindings::iphdr, daddr)) {
        Ok(addr) => addr.0,
        Err(e) => return Err(e as i32),
    };

    let packet_info = PacketInfo {
        protocol,
        src_addr,
        dst_addr,
    };

    EVENTS.output(&ctx, &packet_info, 0);

    Ok(aya_bindings::TC_ACT_OK)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
