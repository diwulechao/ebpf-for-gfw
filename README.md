# ebpf-for-gfw

### Countering GFW Active Probing with an eBPF-Based Whitelist Firewall

This project provides an eBPF-based XDP solution designed to counter active probing from the Great Firewall (GFW) by employing a whitelist mechanism.

---

## How It Works

### TCP Traffic
- The eBPF program inspects every **TCP SYN** packet directed to the VPN port (`443`) and server prefix (`10.0.x.x`).
- Packets are:
  - **Allowed** if they match the whitelist (whitelist operates on `/24` subnets, not `/32`).
  - **Dropped** if they do not match.

### UDP Traffic
- The eBPF program monitors **UDP** packets directed to a specified port range (`1000-2000`) and the server prefix (`10.0.x.x`).
- If a packet matches the signature set by the `.ps1` script, the source IP `/24` prefix is added to the whitelist.

---

## Client-Side Script
A **Windows PowerShell script (`.ps1`)**:
- Runs on the client side.
- Attempts to whitelist the client's source IP every 30 seconds.

---

## Limitations
This solution is not perfect:
- **Replay Attacks**: If GFW performs a replay attack on the UDP whitelist port, it may bypass the whitelist. However:
  - GFW's active probes are unlikely to replay packets this small.
  - Even if replayed, it is improbable to use the same source IP and correct VPN port for a follow-up Shadowsocks probe.

---

## Potential Improvements

### Stateless Challenge-Response Mechanism
1. **Legit Client** → **Server**: `hello`
2. **Server** → **Legit Client**: Responds with the client’s source IP.
3. **Legit Client** → **Server**: Returns a hash of the data from Step 2.
4. **Server**: Adds the client’s source IP to the whitelist if the hash matches.

- **GFW Probe Example**:
  - **GFW Probe** → **Server**: `hello`
  - **Server** → **Probe**: Probe’s source IP.
  - **Probe** → **Server**: A replay hash of a legit client’s source IP.
  - Mismatch between hashes → Probe fails.

### Stateful Challenge-Response Mechanism
Requires an **eBPF LRU Map** to store random challenges.

1. **Legit Client** → **Server**: `hello`
2. **Server** → **Legit Client**: Sends a `random_number` and stores it (`ebpf_lru_map[client_source_ip] = random_number`).
3. **Legit Client** → **Server**: Returns a hash of the random number.
4. **Server**: Adds the client’s source IP to the whitelist if the hash matches.

- **GFW Probe Example**:
  - **GFW Probe** → **Server**: `hello`
  - **Server** → **Probe**: Sends a different random number and stores it (`ebpf_lru_map[probe_source_ip] = another_random_number`).
  - **Probe** → **Server**: Replays a hash of the previous challenge.
  - Mismatch between hashes → Probe fails.

---
