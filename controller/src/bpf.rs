use crate::network::network_probe::NetworkProbeSkelBuilder;
use crate::syscall::{sycallprobe::SyscallSkelBuilder, SyscallEventData};
use crate::{error::Error, network::NetworkEventData};
use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, PerfBufferBuilder};
use std::mem::MaybeUninit;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::{task, task::JoinHandle};

pub fn ebpf_handle(
    network_event_sender: Sender<NetworkEventData>,
    syscall_event_sender: Sender<SyscallEventData>,
    mut rx: Receiver<u64>,
) -> JoinHandle<Result<(), Error>> {
    task::spawn_blocking(move || {
        let mut open_object = MaybeUninit::uninit();
        let skel_builder = NetworkProbeSkelBuilder::default();
        let network_probe_skel = skel_builder.open(&mut open_object).unwrap();
        let mut network_sk = network_probe_skel.load().unwrap();
        network_sk.attach().unwrap();

        let mut open_object = MaybeUninit::uninit();

        let skel_builder = SyscallSkelBuilder::default();
        let syscall_probe_skel = skel_builder.open(&mut open_object).unwrap();
        let mut syscall_sk = syscall_probe_skel.load().unwrap();
        syscall_sk.attach().unwrap();

        let network_perf = PerfBufferBuilder::new(&network_sk.maps.tracept_events)
            .sample_cb(move |_cpu, data: &[u8]| {
                let network_event_data: NetworkEventData =
                    unsafe { *(data.as_ptr() as *const NetworkEventData) };

                if let Err(e) = network_event_sender.blocking_send(network_event_data) {
                    // eprintln!("Failed to send TCP event: {:?}", e);
                    // TODO: If SendError, possibly the receiver is closed, restart the controller
                }
            })
            .build()
            .unwrap();

        let syscall_perf = PerfBufferBuilder::new(&syscall_sk.maps.syscall_events)
            .sample_cb(move |_cpu: i32, data: &[u8]| {
                let syscall_event_data: SyscallEventData =
                    unsafe { *(data.as_ptr() as *const SyscallEventData) };
                if let Err(e) = syscall_event_sender.blocking_send(syscall_event_data) {
                    //eprintln!("Failed to send Syscall event: {:?}", e);
                    //TODO: If SendError, possibly the receiver is closed, restart the controller
                }
            })
            .build()
            .unwrap();

        loop {
            network_perf
                .poll(std::time::Duration::from_millis(100))
                .unwrap();
            syscall_perf
                .poll(std::time::Duration::from_millis(100))
                .unwrap();

            // Process any incoming messages from the pod watcher
            if let Ok(inum) = rx.try_recv() {
                network_sk
                    .maps
                    .inode_num
                    .update(&inum.to_ne_bytes(), &1_u32.to_ne_bytes(), MapFlags::ANY)
                    .unwrap();
                syscall_sk
                    .maps
                    .inode_num
                    .update(&inum.to_ne_bytes(), &1_u32.to_ne_bytes(), MapFlags::ANY)
                    .unwrap();
            }
        }
    })
}
