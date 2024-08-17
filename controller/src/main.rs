// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::str;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::bail;
use anyhow::Result;
use futures::channel::mpsc::Receiver;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::PerfBufferBuilder;

use plain::Plain;
use kube_guardian::models::PodInspect;
use kube_guardian::tcp;
use kube_guardian::tcp::handle_event;
use kube_guardian::tcp::TcpData;
use kube_guardian::watcher::watch_pods;
use procfs::net::udp;
use std::thread;
use time::macros::format_description;
use time::OffsetDateTime;





use kube_guardian::watcher::tcpprobe::TcpProbeSkelBuilder;
use udpprobe::UdpProbeSkelBuilder;


mod syscall {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/syscall.skel.rs"
    ));
}

mod xdp {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/xdp.skel.rs"
    ));
}

mod udpprobe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/udp_probe.skel.rs"
    ));
}





use syscall::*;
use xdp::XdpSkelBuilder;


// fn handle_event(_cpu: i32, data: &[u8]) {
//     let mut event = syscall::types::event::default();
//     plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");

//     let now = if let Ok(now) = OffsetDateTime::now_local() {
//         let format = format_description!("[hour]:[minute]:[second]");
//         now.format(&format)
//             .unwrap_or_else(|_| "00:00:00".to_string())
//     } else {
//         "00:00:00".to_string()
//     };

//     let task = str::from_utf8(&event.task).unwrap();

//     println!(
//         "{:8} {:16} {:<7} {:<14}",
//         now,
//         task.trim_end_matches(char::from(0)),
//         event.pid,
//         event.delta_us
//     );
// }



#[repr(C)]
pub struct UdpData {
    pub inum: u64,
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} events on CPU {cpu}");
}


#[tokio::main]
async fn main() -> Result<()> {
    init_logger();
    let c: Arc<tokio::sync::Mutex<BTreeMap<u64, PodInspect>>> = Arc::new(tokio::sync::Mutex::new(BTreeMap::new()));

    // pod watcher
    let node_name = env::var("CURRENT_NODE").expect("cannot find node name: CURRENT_NODE ");
    let (tx, rx) = std::sync::mpsc::channel();
    let pod_c = Arc::clone(&c);
    let pods = tokio::spawn(
        
        async move {
        watch_pods( node_name, tx,pod_c).await;
    });
  
    let rx_thread:Arc<Mutex<std::sync::mpsc::Receiver<u64>>> = Arc::new(Mutex::new(rx));
    thread::scope(|s| {
        let rx_thread_tcp = Arc::clone(&rx_thread);
        // let rx_thread_udp = Arc::clone(&rx_thread);
        let container_map_tcp =  Arc::clone(&c);
        // let container_map_udp =  Arc::clone(&c);
        s.spawn(move|| { 
        
            let mut open_object = MaybeUninit::uninit();
            let skel_builder = TcpProbeSkelBuilder::default();
            let tcp_probe_skel = skel_builder.open(&mut open_object).unwrap();
            let mut sk = tcp_probe_skel.load().unwrap();
            sk.attach().unwrap();
            let perf = PerfBufferBuilder::new(&sk.maps.tracept_events).sample_cb(|_cpu, data: &[u8]| {
            let data: &TcpData = unsafe { &*(data.as_ptr() as *const TcpData) };
                // get the inum data
                let inum =  data.inum;
                let c_locked = tokio::runtime::Runtime::new().unwrap().block_on(container_map_tcp.lock());
                // get pod details
                let p : Option<&PodInspect> = c_locked.get(&inum);
                if p.is_some() {
                    handle_event(data, p.unwrap());
                }
            }).build().unwrap();
            let perf_udp = PerfBufferBuilder::new(&sk.maps.udp_events).sample_cb(|_cpu, data: &[u8]| {
                let data: &TcpData = unsafe { &*(data.as_ptr() as *const TcpData) };
                    // get the inum data
                    let inum =  data.inum;
                    let c_locked = tokio::runtime::Runtime::new().unwrap().block_on(container_map_tcp.lock());
                    // get pod details
                    let p : Option<&PodInspect> = c_locked.get(&inum);
                    if p.is_some() {
                        handle_event(data, p.unwrap());
                    }
                }).build().unwrap();
            loop {
                perf.poll(std::time::Duration::from_millis(100)).unwrap();
                perf_udp.poll(std::time::Duration::from_millis(100)).unwrap();
                if let Ok(inum) = rx_thread_tcp.lock().unwrap().try_recv() {
                    println!("I am here in  tcp");
                    sk.maps.inode_num.update(&inum.to_ne_bytes(), &1_u32.to_ne_bytes(), MapFlags::ANY).unwrap();
                }
            }
        });
        // s.spawn(move|| {
        //     let mut open_object = MaybeUninit::uninit();
        //     let skel_builder = UdpProbeSkelBuilder::default();
        //     let udp_probe_skel = skel_builder.open(&mut open_object).unwrap();
        //     let mut sk = udp_probe_skel.load().unwrap();
        //     sk.attach();
        //     let perf = PerfBufferBuilder::new(&sk.maps.udp_events).sample_cb(|_cpu, data: &[u8]| {
        //         let data: &UdpData = unsafe { &*(data.as_ptr() as *const UdpData) };
        //             // get the inum data
        //             let inum =  data.inum;
        //             let c_locked = tokio::runtime::Runtime::new().unwrap().block_on(container_map_udp.lock());
        //             // get pod details
        //             let p : Option<&PodInspect> = c_locked.get(&inum);
        //             if p.is_some() {
        //                 let src = u32::from_be(data.saddr);
        //                 let dst = u32::from_be(data.daddr);
        //                 let sport = data.sport;
        //                 let dport = data.dport;
        //                 println!( "udpData {}-> {}:{}, {}:{}", inum, IpAddr::V4(Ipv4Addr::from(src)).to_string(),sport,IpAddr::V4(Ipv4Addr::from(dst)).to_string(), dport);
        //             }
        //         }).build().unwrap();
        //         loop {
        //             perf.poll(std::time::Duration::from_millis(100)).unwrap();
        //             // TCP is already updating the values in maps
        //             if let Ok(inum) = rx_thread_udp.lock().unwrap().try_recv() {
        //                 println!("I am here in  udp");
        //                 sk.maps.inode_num.update(&inum.to_ne_bytes(), &1_u32.to_ne_bytes(), MapFlags::ANY).unwrap();
        //             }
        //         }
        // });
    });

    println!("Now waiting on tokio");

    // Join async tasks and wait for them to complete
        let _ = tokio::runtime::Runtime::new().unwrap().block_on(async {
        tokio::join!(pods);
     });

    println!("All tasks completed.");
    // syscall
    // let mut skel_builder = SyscallSkelBuilder::default();
    // let open_skel = skel_builder.open()?;
    // // Begin tracing
    // let mut skel = open_skel.load()?;
    // skel.attach()?;
    // let perf = PerfBufferBuilder::new(&skel.maps_mut().events())
    // .sample_cb(|_cpu, data: &[u8]| {
    //     let data: &Data = unsafe { &*(data.as_ptr() as *const Data) };
    //     handle_event(data);
    // })
    // .build()?;

    // xdp
    // let mut xdp_skel_builder = XdpSkelBuilder::default();
    // let xdp_open_skel = xdp_skel_builder.open()?;
    // let mut xdpSkel = xdp_open_skel.load()?;
    // let link = xdpSkel.progs_mut().xdp_trace_packets().attach_xdp(7)?;
    // println!("Link {:?}", link);
    
    // let perf = PerfBufferBuilder::new(&xdpSkel.maps_mut().xdp_events())
    // .sample_cb(|_cpu, data: &[u8]| {
    //     let data: &Data = unsafe { &*(data.as_ptr() as *const Data) };
    //     handle_event(data);
    // })
    // .build()?;

    // tracepoint

    


//     let link = skel.progs_mut().xdp_pass().attach_xdp(opts.ifindex)?;
// .

// load all the ebpf program
// watcher to watch all the pods
// get the inum when the pod is created and store in maps which will be used in filtering
// store key as inum and value as pod details

    Ok(())

}



pub fn init_logger() {
    // check the rust log
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info")
    }
    if std::env::var("RUST_LOG").unwrap().to_lowercase().eq("info") {
        std::env::set_var("RUST_LOG", "info,kube_client=off");
    } else {
        std::env::set_var(
            "RUST_LOG",
            "debug,kube_client=off,tower=off,hyper=off,h2=off,rustls=off,reqwest=off",
        );
    }

    let timer = time::format_description::parse(
        "[year]-[month padding:zero]-[day padding:zero] [hour]:[minute]:[second]",
    )
    .expect("Time Error");
    let time_offset = time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC);
    let timer = tracing_subscriber::fmt::time::OffsetTime::new(time_offset, timer);

    // Initialize the logger
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_timer(timer)
        .init();
}