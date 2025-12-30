//! Transport layer benchmarks.
//!
//! Measures throughput and latency under various conditions including
//! packet loss simulation.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use scf::transport::{
    CongestionController, CongestionConfig,
    FecEncoder, FecDecoder,
    Packet, PacketType,
    ReliabilityLayer, ReliabilityConfig,
};
use bytes::Bytes;

fn bench_packet_encode(c: &mut Criterion) {
    let payload = vec![0u8; 1200];

    let mut group = c.benchmark_group("packet_encode");
    group.throughput(Throughput::Bytes(1200));

    group.bench_function("1200_bytes", |b| {
        b.iter(|| {
            let packet = Packet::data(1, 42, Bytes::from(payload.clone()));
            black_box(packet.encode())
        })
    });

    group.finish();
}

fn bench_packet_decode(c: &mut Criterion) {
    let payload = vec![0u8; 1200];
    let packet = Packet::data(1, 42, Bytes::from(payload));
    let encoded = packet.encode();

    let mut group = c.benchmark_group("packet_decode");
    group.throughput(Throughput::Bytes(encoded.len() as u64));

    group.bench_function("1200_bytes", |b| {
        b.iter(|| {
            black_box(Packet::decode(encoded.clone()).unwrap())
        })
    });

    group.finish();
}

fn bench_fec_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec_encode");

    // Test with different group sizes
    for group_size in [4, 8, 16] {
        group.bench_function(format!("group_{}", group_size), |b| {
            b.iter(|| {
                let mut encoder = FecEncoder::new(group_size, 1);
                let mut repairs = Vec::new();

                for i in 0..group_size {
                    let data = Bytes::from(vec![i as u8; 1200]);
                    repairs.extend(encoder.add_packet(i as u64, data));
                }

                black_box(repairs)
            })
        });
    }

    group.finish();
}

fn bench_fec_decode_recovery(c: &mut Criterion) {
    // Setup: create encoder and generate repair packet
    let mut encoder = FecEncoder::new(4, 1);
    let packets: Vec<Bytes> = (0..4)
        .map(|i| Bytes::from(vec![i as u8; 1200]))
        .collect();

    let mut repairs = Vec::new();
    for (i, pkt) in packets.iter().enumerate() {
        repairs.extend(encoder.add_packet(i as u64, pkt.clone()));
    }

    c.bench_function("fec_decode_recover_one", |b| {
        b.iter(|| {
            let mut decoder = FecDecoder::new(100);

            // Add all packets except one
            decoder.add_data(0, packets[0].clone());
            decoder.add_data(1, packets[1].clone());
            // Skip packet 2 (lost)
            decoder.add_data(3, packets[3].clone());

            decoder.mark_lost(2);
            decoder.add_repair(repairs[0].clone());

            black_box(decoder.try_recover())
        })
    });
}

fn bench_congestion_controller(c: &mut Criterion) {
    c.bench_function("congestion_on_ack", |b| {
        b.iter(|| {
            let mut cc = CongestionController::new(CongestionConfig::default());

            // Simulate 100 packet sends and acks
            for i in 0..100 {
                cc.on_send(1200);
                cc.on_ack(1200, 50000 + (i * 100)); // Varying RTT
            }

            black_box(cc.cwnd())
        })
    });
}

fn bench_congestion_with_loss(c: &mut Criterion) {
    c.bench_function("congestion_with_5pct_loss", |b| {
        b.iter(|| {
            let mut cc = CongestionController::new(CongestionConfig::default());

            // Simulate 100 packets with 5% loss
            for i in 0..100 {
                cc.on_send(1200);

                if i % 20 == 0 {
                    // 5% loss
                    cc.on_loss(1200);
                } else {
                    cc.on_ack(1200, 50000);
                }
            }

            black_box(cc.cwnd())
        })
    });
}

fn bench_reliability_layer(c: &mut Criterion) {
    c.bench_function("reliability_send_receive", |b| {
        b.iter(|| {
            let mut layer = ReliabilityLayer::new(ReliabilityConfig::default());

            // Send 100 packets
            for i in 0..100 {
                let packet = Packet::data(1, i, Bytes::from(vec![0u8; 100]));
                layer.on_send(packet);
            }

            // Receive ACKs
            for i in 0..100 {
                let ack = Packet::ack(1, i, 65536);
                layer.on_receive(&ack);
            }

            black_box(layer.pending_count())
        })
    });
}

fn bench_reliability_reorder(c: &mut Criterion) {
    c.bench_function("reliability_out_of_order", |b| {
        b.iter(|| {
            let mut layer = ReliabilityLayer::new(ReliabilityConfig::default());

            // Receive packets out of order
            let order = [5, 3, 1, 0, 2, 4, 6, 8, 7, 9];

            for &seq in &order {
                let packet = Packet::data(1, seq, Bytes::from(vec![seq as u8; 100]));
                layer.on_receive(&packet);
            }

            black_box(layer.next_expected())
        })
    });
}

fn bench_throughput_simulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput_simulation");
    group.throughput(Throughput::Bytes(1_000_000)); // 1 MB

    group.bench_function("1mb_no_loss", |b| {
        b.iter(|| {
            let mut cc = CongestionController::new(CongestionConfig::default());
            let mut total_bytes = 0u64;

            while total_bytes < 1_000_000 {
                if cc.can_send() {
                    let bytes = cc.available_cwnd().min(1200);
                    cc.on_send(bytes);
                    total_bytes += bytes as u64;
                    cc.on_ack(bytes, 50000); // 50ms RTT
                }
            }

            black_box(total_bytes)
        })
    });

    group.bench_function("1mb_20pct_loss", |b| {
        let mut loss_counter = 0u32;

        b.iter(|| {
            let mut cc = CongestionController::new(CongestionConfig::default());
            let mut total_bytes = 0u64;

            while total_bytes < 1_000_000 {
                if cc.can_send() {
                    let bytes = cc.available_cwnd().min(1200);
                    cc.on_send(bytes);

                    loss_counter += 1;
                    if loss_counter % 5 == 0 {
                        // 20% loss
                        cc.on_loss(bytes);
                    } else {
                        total_bytes += bytes as u64;
                        cc.on_ack(bytes, 50000);
                    }
                }
            }

            black_box(total_bytes)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_packet_encode,
    bench_packet_decode,
    bench_fec_encode,
    bench_fec_decode_recovery,
    bench_congestion_controller,
    bench_congestion_with_loss,
    bench_reliability_layer,
    bench_reliability_reorder,
    bench_throughput_simulation,
);

criterion_main!(benches);
