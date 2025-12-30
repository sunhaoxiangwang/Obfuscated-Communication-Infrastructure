# Evaluation Methodology

This document describes the empirical validation procedures for the Steganographic Communication Framework (SCF).

## 1. Traffic Entropy Analysis

### 1.1 KL Divergence Test

**Objective**: Demonstrate that SCF traffic is statistically indistinguishable from legitimate TLS 1.3/HTTPS traffic.

**Methodology**:

```
D_KL(P || Q) = Σ P(x) * log(P(x) / Q(x))
```

Where:
- P(x) = Distribution of SCF packet sizes/timings
- Q(x) = Distribution of baseline HTTPS traffic (captured from Nginx)

**Acceptance Criteria**: D_KL < 0.1 (indicating near-identical distributions)

**Test Procedure**:

1. Capture 10,000 packets of legitimate Nginx HTTPS traffic
2. Generate 10,000 packets of SCF traffic with padding/timing enabled
3. Compute KL divergence for:
   - Packet size distribution
   - Inter-packet timing distribution
   - TLS record length distribution

### 1.2 Entropy Analysis

**Test**: Shannon entropy of packet payloads should match encrypted data expectations.

```
H(X) = -Σ P(x) * log₂(P(x))
```

**Expected Result**: H ≈ 8.0 bits per byte (maximum entropy for encrypted data)

## 2. ML Classification Test

### 2.1 Binary Classification

**Objective**: Validate that ML classifiers cannot distinguish SCF traffic from legitimate HTTPS.

**Models Tested**:
- Random Forest (100 trees)
- Convolutional Neural Network (1D convolutions on packet sequences)
- Long Short-Term Memory (LSTM) network

**Features Extracted**:
- Packet sizes (histogram, mean, std, percentiles)
- Inter-arrival times (histogram, mean, std)
- Burst patterns (packets per burst, burst duration)
- TLS record structure (handshake patterns)

**Training Data**:
- 50% legitimate HTTPS traffic (Nginx, CloudFlare, AWS)
- 50% SCF obfuscated traffic

**Acceptance Criteria**:
- Accuracy ≤ 55% (within margin of random guessing)
- AUC-ROC ≤ 0.55

### 2.2 Test Procedure

```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
import numpy as np

# Load traffic samples
X_legit = load_https_features("captures/legitimate/")
X_scf = load_scf_features("captures/scf/")

# Create balanced dataset
X = np.vstack([X_legit, X_scf])
y = np.hstack([np.zeros(len(X_legit)), np.ones(len(X_scf))])

# 10-fold cross validation
clf = RandomForestClassifier(n_estimators=100, random_state=42)
scores = cross_val_score(clf, X, y, cv=10, scoring='accuracy')

print(f"Accuracy: {scores.mean():.3f} (+/- {scores.std() * 2:.3f})")
assert scores.mean() < 0.55, "Traffic is distinguishable!"
```

## 3. Resilience Benchmarks

### 3.1 Packet Loss Simulation

**Objective**: Demonstrate >90% goodput under 20% random packet loss.

**Test Environment**:
- tc (traffic control) for network emulation
- netem for packet loss injection

**Configuration**:
```bash
# Server side
tc qdisc add dev eth0 root netem loss 20%

# Client side
tc qdisc add dev eth0 root netem loss 20%
```

**Metrics Collected**:
- Goodput (useful bytes delivered / time)
- Retransmission rate
- FEC recovery rate
- End-to-end latency (P50, P95, P99)

### 3.2 Test Matrix

| Loss Rate | FEC Enabled | Expected Goodput |
|-----------|-------------|------------------|
| 0%        | No          | ~100%            |
| 0%        | Yes         | ~80% (FEC overhead) |
| 10%       | No          | ~70%             |
| 10%       | Yes         | ~90%             |
| 20%       | No          | ~50%             |
| 20%       | Yes         | >90%             |
| 30%       | No          | ~30%             |
| 30%       | Yes         | >80%             |

### 3.3 Benchmark Script

```rust
async fn benchmark_throughput(loss_rate: f64, enable_fec: bool) -> BenchmarkResult {
    let config = TransportConfig {
        enable_fec,
        fec_ratio: 0.2,
        ..Default::default()
    };

    let client = create_test_client(config).await;
    let server = create_test_server(config).await;

    // Configure network emulation
    set_loss_rate(loss_rate);

    // Transfer 10 MB
    let data = vec![0u8; 10 * 1024 * 1024];
    let start = Instant::now();

    client.send(&data).await.unwrap();
    let received = server.recv_all().await;

    let elapsed = start.elapsed();
    let goodput = received.len() as f64 / elapsed.as_secs_f64();

    BenchmarkResult {
        loss_rate,
        enable_fec,
        goodput_mbps: goodput * 8.0 / 1_000_000.0,
        data_integrity: received == data,
    }
}
```

## 4. Latency Overhead Measurement

### 4.1 RTT Breakdown

**Objective**: Verify overhead does not exceed 15% of standard TLS RTT.

**Components Measured**:
1. TLS handshake time (baseline)
2. SCF handshake time (with REALITY)
3. Per-packet encryption overhead
4. Padding overhead
5. Timing obfuscation overhead

### 4.2 Test Procedure

```rust
async fn measure_handshake_overhead() -> OverheadResult {
    // Baseline: standard TLS 1.3 to cover server
    let baseline_times: Vec<Duration> = (0..100)
        .map(|_| measure_tls_handshake("cover.example.com"))
        .collect();

    // SCF: REALITY protocol to our server
    let scf_times: Vec<Duration> = (0..100)
        .map(|_| measure_scf_handshake())
        .collect();

    let baseline_p50 = percentile(&baseline_times, 50);
    let scf_p50 = percentile(&scf_times, 50);

    let overhead = (scf_p50 - baseline_p50) / baseline_p50;

    OverheadResult {
        baseline_p50,
        scf_p50,
        overhead_percent: overhead * 100.0,
    }
}
```

**Acceptance Criteria**: overhead_percent < 15%

## 5. Security Audit Procedures

### 5.1 Zero-Log Verification

**Objective**: Confirm RAM-only data processing.

**Audit Checklist**:

- [ ] No file system writes during session handling
- [ ] Session data stored in volatile memory only
- [ ] Automatic session expiration and cleanup
- [ ] Secret key material zeroized on drop
- [ ] No logging of user-identifiable information

**Verification Method**:

1. Run server under strace/dtrace to monitor syscalls
2. Verify no write() calls to persistent storage
3. Memory dump analysis after session termination
4. Verify zeroization of secret material

```bash
# Trace file operations
strace -e trace=write,open,creat -f ./scf-server --config test.toml

# Verify no writes to disk (excluding stdout/stderr)
# Should see only fd 1 and 2
```

### 5.2 Forward Secrecy Verification

**Test**: Compromise of long-term keys should not reveal past sessions.

**Procedure**:

1. Establish session and exchange messages
2. Capture encrypted traffic
3. "Compromise" server's static key
4. Attempt to decrypt captured traffic
5. Verify decryption fails (ephemeral keys are gone)

### 5.3 Cryptographic Implementation Review

**Areas Reviewed**:
- Constant-time comparison for authentication tags
- Proper nonce handling (no reuse)
- Key derivation follows best practices
- Zeroization of sensitive data
- No timing side channels

## 6. Cross-Platform Validation

### 6.1 Platform Matrix

| Platform       | Architecture | Test Status |
|----------------|--------------|-------------|
| Linux x86_64   | x86-64       | Required    |
| Linux ARM64    | aarch64      | Required    |
| macOS x86_64   | x86-64       | Required    |
| macOS ARM64    | aarch64      | Required    |
| Windows x86_64 | x86-64       | Required    |
| Android        | ARM64/ARM32  | Required    |
| iOS            | ARM64        | Required    |

### 6.2 Mobile Performance

**Constraints**:
- Battery impact < 5% over 1 hour idle connection
- Memory usage < 10 MB resident
- CPU usage < 2% average during data transfer

## 7. Automated Test Suite

### 7.1 Continuous Integration

```yaml
# .github/workflows/ci.yml
name: SCF CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --all-features
      - run: cargo bench --no-run  # Compile benchmarks

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo audit
      - run: cargo deny check

  traffic_analysis:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4
      - run: pip install -r tests/requirements.txt
      - run: python tests/traffic_analysis.py
```

### 7.2 Property-Based Testing

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn encrypt_decrypt_roundtrip(
        plaintext in prop::collection::vec(any::<u8>(), 0..10000),
        key in prop::array::uniform32(any::<u8>()),
    ) {
        let aead = Aead::new(&AeadKey::from_bytes(key));
        let nonce = Nonce::new(0);

        let ciphertext = aead.encrypt(&nonce, &plaintext, b"").unwrap();
        let decrypted = aead.decrypt(&nonce, &ciphertext, b"").unwrap();

        prop_assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn padding_preserves_data(
        data in prop::collection::vec(any::<u8>(), 1..1000),
    ) {
        let model = TrafficModel::new(TrafficProfile::Https);
        let oracle = PaddingOracle::new(
            PaddingStrategy::MatchDistribution,
            0.5,
            &model,
        );

        let padded = oracle.pad(&data);
        let unpadded = oracle.unpad(&padded).unwrap();

        prop_assert_eq!(data, unpadded);
    }
}
```

## 8. Results Documentation

All test results should be documented with:

1. Test environment specifications
2. Exact configuration used
3. Raw data files
4. Statistical analysis
5. Comparison to acceptance criteria
6. Reproducibility instructions

Results are stored in `docs/results/` with timestamp-based naming.
