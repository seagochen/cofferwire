#![no_main]

use cofferwire_relay::{
    MessageId, Principal, QueueConfig, QueueId, QueueLimits, Relay, Timestamp, Ttl,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut relay = Relay::new();
    let queue = QueueId::from_bytes([1; 32]);
    let sender = Principal::from_bytes([2; 32]);
    let recipient = Principal::from_bytes([3; 32]);
    let limits = QueueLimits::new(8, 1024).expect("fixed nonzero limits");
    let _ = relay.create_queue(queue, QueueConfig::new(sender, recipient, limits));
    for (step, input) in data.chunks(34).take(256).enumerate() {
        let action = input.first().copied().unwrap_or(0) % 5;
        let now = Timestamp::from_secs(u64::from(input.get(1).copied().unwrap_or(0)));
        let mut id = [0; 32];
        let source = input.get(2..).unwrap_or_default();
        id[..source.len()].copy_from_slice(source);
        let id = MessageId::from_bytes(id);
        match action {
            0 => { let ttl = Ttl::from_secs(1 + step as u64).expect("nonzero"); let _ = relay.send(queue, sender, id, source.to_vec(), now, ttl); }
            1 => { let _ = relay.fetch(queue, recipient, now); }
            2 => { let _ = relay.acknowledge(queue, recipient, id, now); }
            3 => { let _ = relay.send(queue, Principal::from_bytes([9; 32]), id, source.to_vec(), now, Ttl::from_secs(1).expect("nonzero")); }
            _ => { let _ = relay.delete_queue(queue, recipient); }
        }
    }
});
