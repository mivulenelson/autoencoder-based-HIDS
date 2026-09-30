"""
src/ingestion/parser.py
-----------------------
Converts raw Scapy packets into the 22 flow-based behavioral feature vectors
defined in the project proposal (Table 3) and implemented in training_validated.ipynb.

Feature groups (must match FEATURE_NAMES in training_validated.ipynb exactly):
    Timing   (6): flow_duration, fwd_iat_mean, fwd_iat_std, fwd_iat_min,
                  fwd_iat_max, fwd_iat_total
    Volume   (5): fwd_pkt_len_mean, fwd_pkt_len_std, fwd_pkt_len_min,
                  fwd_pkt_len_max, total_fwd_bytes
    Rate     (2): flow_pkts_per_sec, flow_bytes_per_sec
    Burst    (3): pkt_len_variance, burst_ratio, active_time_ratio
    Session  (3): pkt_count, unique_ttl_count, ttl_mean
    Protocol (3): tcp_flag_ratio, has_udp, has_tcp

All features are computed from L3/L4 headers only — no payload bytes are
inspected, preserving the system's zero-decryption guarantee (proposal §1.6.1).

BUG FIXED — real IP addresses never reached the GUI
-----------------------------------------------------
parse_to_features() previously returned ONLY the 22-element numeric feature
vector, discarding flow_key — which is where the flow's real
(src_ip, dst_ip, src_port, dst_port, protocol) 5-tuple actually lives.

Fixed by having parse_to_features() (and flush()) return a
(features, flow_meta) tuple, where flow_meta is built directly from that
flow's own flow_key — guaranteeing the IP/port/protocol always belongs to
the exact flow that produced the feature vector, with no separate tracking,
no locks, and no race conditions needed.

IMPROVEMENTS — tied to eda_encrypted_subset.ipynb / training_validated.ipynb
------------------------------------------------------------------------------
1. NEW: is_encrypted flag on flow_meta. eda_encrypted_subset.ipynb's Section
   3 established the concept of isolating TLS/HTTPS-class traffic via
   ENCRYPTED_PORTS as a proxy for encryption (CIC-IDS2017 has no
   JA3/handshake metadata to determine this directly). That concept
   previously existed only in the offline notebooks — the live capture
   pipeline had no equivalent, so an operator could never filter alerts
   by "was this actually encrypted traffic" the way the EDA/validation
   notebooks now can. This closes that gap end-to-end: EDA proves the
   claim on offline data, training validates it quantitatively, and now
   the live system tags every flow the same way, so Reports/forensic
   queries can filter on it too.

   IMPORTANT DIFFERENCE FROM THE NOTEBOOK VERSION: eda_encrypted_subset.ipynb
   checks `Destination Port in ENCRYPTED_PORTS` because CICFlowMeter already
   merges each session into ONE bidirectional flow record. PacketParser here
   tracks flows UNIDIRECTIONALLY — a server's response packets (src_port=443)
   form a SEPARATE flow_key from the client's request packets (dst_port=443).
   Checking dst_port alone would silently miss the server->client half of
   every TLS session. This checks BOTH src_port and dst_port against
   ENCRYPTED_PORTS so both directions of a session are tagged consistently.

2. NEW: defensive length assertion in _compute_features() — catches an
   accidental feature-count drift (e.g. someone adds/removes a line in the
   return list without updating FEATURE_NAMES) immediately and loudly,
   rather than silently producing a wrong-length vector that fails later
   with a less obvious error deep inside evaluator.py's np.array reshape.

3. DOCUMENTED LIMITATION (not fixed — disclosed, matching this project's
   established pattern of honest scope statements): this parser only
   matches IPv4 (`packet.haslayer(IP)` is Scapy's IPv4 layer specifically).
   IPv6 traffic is silently NOT captured, parsed, or counted anywhere.
   See the note near the IP-layer check below.
"""

import time
import logging
import numpy as np
from scapy.layers.inet import IP, TCP, UDP

logger = logging.getLogger("HIDS_Parser")

# Must stay in sync with training_validated.ipynb -> FEATURE_NAMES (22 elements)
FEATURE_NAMES = [
    # Timing
    "flow_duration",
    "fwd_iat_mean",
    "fwd_iat_std",
    "fwd_iat_min",
    "fwd_iat_max",
    "fwd_iat_total",
    # Volume
    "fwd_pkt_len_mean",
    "fwd_pkt_len_std",
    "fwd_pkt_len_min",
    "fwd_pkt_len_max",
    "total_fwd_bytes",
    # Rate
    "flow_pkts_per_sec",
    "flow_bytes_per_sec",
    # Burstiness
    "pkt_len_variance",
    "burst_ratio",
    "active_time_ratio",
    # Session
    "pkt_count",
    "unique_ttl_count",
    "ttl_mean",
    # Protocol
    "tcp_flag_ratio",
    "has_udp",
    "has_tcp",
]

assert len(FEATURE_NAMES) == 22, "Feature list must contain exactly 22 entries"

# Minimum packets before a flow's features are computed and emitted.
# Set to 5 to match extract_22_features() in training_validated.ipynb.
MIN_FLOW_PACKETS = 5

# Ports treated as TLS/HTTPS-encrypted for the is_encrypted flow_meta flag.
# MUST match ENCRYPTED_PORTS in eda_encrypted_subset.ipynb Section 3, so the
# live system's "encrypted traffic" concept stays consistent with the
# offline analysis and validation that established it. This is a
# literature-standard proxy (destination-port heuristic), not a
# cryptographic guarantee — there is no packet-level TLS handshake
# inspection here, consistent with the project's zero-decryption design.
ENCRYPTED_PORTS = {443, 8443, 993, 995, 465, 587}


class PacketParser:
    """
    Stateful per-flow feature extractor.

    Each unique (src_ip, dst_ip, src_port, dst_port, proto) 5-tuple is tracked
    as a separate flow.  Once MIN_FLOW_PACKETS have been collected the flow is
    finalised, its 22 features computed, and the flow state is cleared so memory
    stays bounded.

    parse_to_features() and flush() both return (features, flow_meta) tuples
    (or None if a flow is still accumulating) — flow_meta carries the real
    src_ip/dst_ip/src_port/dst_port/protocol/is_encrypted for that exact
    flow, so callers never need to track any of this separately.

    KNOWN LIMITATION — IPv4 only. This parser matches packets via
    `packet.haslayer(IP)`, which is Scapy's IPv4 layer specifically. IPv6
    traffic is silently NOT captured, parsed, or counted by this system.
    Adding IPv6 support would require also matching
    `scapy.layers.inet6.IPv6` and adapting the flow-key/TTL(hop-limit)
    logic below, since IPv6 headers differ from IPv4 in field names and
    semantics. This is disclosed here as a stated scope limitation rather
    than silently absent.
    """

    def __init__(self, min_packets: int = MIN_FLOW_PACKETS):
        self._flows: dict = {}
        self._min_packets = min_packets

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse_to_features(self, packet):
        """
        Ingest one Scapy packet and return (features, flow_meta) once the
        flow reaches MIN_FLOW_PACKETS, otherwise return None.

        Args:
            packet: A Scapy packet object captured by HIDSSniffer.

        Returns:
            tuple[list[float], dict] | None —
                features:  22-element feature vector (order matches FEATURE_NAMES)
                flow_meta: {"src_ip", "dst_ip", "src_port", "dst_port",
                            "protocol", "is_encrypted"} taken directly from
                           THIS flow's own 5-tuple key — guaranteed to match
                           the flow that produced `features`.
        """
        # NOTE: haslayer(IP) matches IPv4 only — see class docstring's
        # "KNOWN LIMITATION" note. IPv6 packets are silently skipped here.
        if not packet.haslayer(IP):
            return None

        try:
            ip  = packet[IP]
            now = time.time()
            pkt_len = len(packet)

            # ── Layer-4 header fields ─────────────────────────────────────
            src_port = dst_port = 0
            has_tcp = has_udp = 0
            tcp_flags = 0

            if packet.haslayer(TCP):
                src_port  = packet[TCP].sport
                dst_port  = packet[TCP].dport
                has_tcp   = 1
                tcp_flags = int(packet[TCP].flags)
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                has_udp  = 1

            # 5-tuple flow key (unidirectional) — this IS the real connection
            # identity; flow_meta below is built directly from this, not from
            # any separately-tracked "last seen packet" state.
            flow_key = (ip.src, ip.dst, src_port, dst_port, ip.proto)

            # TTL — available on every IP packet
            ttl = ip.ttl

            # ── Flow state management ────────────────────────────────────
            if flow_key not in self._flows:
                self._flows[flow_key] = {
                    "start_time"    : now,
                    "last_ts"       : now,
                    "pkt_count"     : 1,
                    "total_bytes"   : pkt_len,
                    "iat_list"      : [],           # inter-arrival times
                    "len_list"      : [pkt_len],    # packet lengths
                    "ttl_list"      : [ttl],
                    "tcp_flags_list": [tcp_flags] if has_tcp else [],
                    "has_tcp"       : has_tcp,
                    "has_udp"       : has_udp,
                }
                return None

            flow = self._flows[flow_key]
            iat  = now - flow["last_ts"]

            flow["pkt_count"]      += 1
            flow["total_bytes"]    += pkt_len
            flow["iat_list"].append(iat)
            flow["len_list"].append(pkt_len)
            flow["ttl_list"].append(ttl)
            flow["last_ts"]         = now

            # Merge protocol flags across packets
            if has_tcp:
                flow["has_tcp"] = 1
                flow["tcp_flags_list"].append(tcp_flags)
            if has_udp:
                flow["has_udp"] = 1

            # Emit features once flow is mature enough
            if flow["pkt_count"] >= self._min_packets:
                features = self._compute_features(flow)
                meta     = self._build_meta(flow_key, flow)
                del self._flows[flow_key]   # free state immediately
                return features, meta

            return None

        except Exception as exc:
            logger.exception(f"Parser error on packet: {exc}")
            return None

    def flush(self):
        """
        Force-emit features for all in-progress flows regardless of packet
        count.  Call this on shutdown or periodically to avoid stale flows
        accumulating in memory.

        Returns:
            list[tuple[list[float], dict]] — same (features, flow_meta) shape
            as parse_to_features(), one entry per in-progress flow.
        """
        results = []
        for flow_key, flow in list(self._flows.items()):
            if flow["pkt_count"] >= 2:          # need at least 1 IAT
                try:
                    features = self._compute_features(flow)
                    meta     = self._build_meta(flow_key, flow)
                    results.append((features, meta))
                except Exception:
                    pass
        self._flows.clear()
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_meta(flow_key: tuple, flow: dict) -> dict:
        """
        Builds the network-metadata dict directly from a flow's own 5-tuple
        key — the IP/port/protocol reported for an alert is always the flow
        that ACTUALLY produced it, not a separately tracked "most recent
        packet" value that could belong to a different connection entirely.

        is_encrypted: checks BOTH src_port and dst_port against
        ENCRYPTED_PORTS (not dst_port alone) because flows here are tracked
        UNIDIRECTIONALLY — a TLS session's server-to-client packets have
        src_port=443, not dst_port=443. Checking only dst_port (as
        eda_encrypted_subset.ipynb does, correctly, for CICFlowMeter's
        already-bidirectional flow records) would silently miss half of
        every live TLS session.
        """
        src_ip, dst_ip, src_port, dst_port, proto_num = flow_key

        if flow.get("has_tcp"):
            protocol = "TCP"
        elif flow.get("has_udp"):
            protocol = "UDP"
        else:
            protocol = "IP"   # only L3 info known — no L4 signal available

        is_encrypted = bool(
            src_port in ENCRYPTED_PORTS or dst_port in ENCRYPTED_PORTS
        )

        return {
            "src_ip":       src_ip,
            "dst_ip":       dst_ip,
            "src_port":     src_port,
            "dst_port":     dst_port,
            "protocol":     protocol,
            "is_encrypted": is_encrypted,
        }

    @staticmethod
    def _compute_features(flow: dict) -> list:
        """
        Compute the 22 behavioral metadata features from a completed flow's
        accumulated state.  Order matches FEATURE_NAMES exactly.
        """
        duration = flow["last_ts"] - flow["start_time"]
        safe_dur = max(duration, 1e-9)          # avoid division-by-zero

        iat_arr = np.array(flow["iat_list"]) if flow["iat_list"] else np.array([0.0])
        len_arr = np.array(flow["len_list"], dtype=float)
        ttl_arr = np.array(flow["ttl_list"], dtype=float)

        # ── Burstiness features ──────────────────────────────────────────
        # burst_ratio: fraction of IATs below the mean — dense packet bursts
        iat_mean  = float(iat_arr.mean())
        burst_ratio = float((iat_arr < iat_mean).mean()) if len(iat_arr) > 1 else 0.0
        # active_time_ratio: packet rate as a proxy for how "full" the flow is
        active_time_ratio = float(flow["pkt_count"] / safe_dur)

        # ── Protocol features ────────────────────────────────────────────
        flags_arr      = flow["tcp_flags_list"]
        tcp_flag_ratio = float(np.mean(flags_arr) / 255.0) if flags_arr else 0.0

        # ── TTL features ─────────────────────────────────────────────────
        unique_ttl_count = float(len(set(flow["ttl_list"])))
        ttl_mean         = float(ttl_arr.mean())

        features = [
            # ── Timing ───────────────────────────────────────────────────
            float(duration),                    # flow_duration
            iat_mean,                           # fwd_iat_mean
            float(iat_arr.std()),               # fwd_iat_std
            float(iat_arr.min()),               # fwd_iat_min
            float(iat_arr.max()),               # fwd_iat_max
            float(iat_arr.sum()),               # fwd_iat_total
            # ── Volume ───────────────────────────────────────────────────
            float(len_arr.mean()),              # fwd_pkt_len_mean
            float(len_arr.std()),               # fwd_pkt_len_std
            float(len_arr.min()),               # fwd_pkt_len_min
            float(len_arr.max()),               # fwd_pkt_len_max
            float(len_arr.sum()),               # total_fwd_bytes
            # ── Rate ─────────────────────────────────────────────────────
            float(flow["pkt_count"] / safe_dur),   # flow_pkts_per_sec
            float(flow["total_bytes"] / safe_dur), # flow_bytes_per_sec
            # ── Burstiness ───────────────────────────────────────────────
            float(len_arr.var()),               # pkt_len_variance
            burst_ratio,                        # burst_ratio
            active_time_ratio,                  # active_time_ratio
            # ── Session ──────────────────────────────────────────────────
            float(flow["pkt_count"]),           # pkt_count
            unique_ttl_count,                   # unique_ttl_count
            ttl_mean,                           # ttl_mean
            # ── Protocol ─────────────────────────────────────────────────
            tcp_flag_ratio,                     # tcp_flag_ratio
            float(flow["has_udp"]),             # has_udp
            float(flow["has_tcp"]),             # has_tcp
        ]

        # NEW: defensive length check — fails loudly and immediately if a
        # future edit adds/removes a feature line without updating
        # FEATURE_NAMES, instead of silently producing a wrong-length
        # vector that only surfaces as a confusing shape error much later
        # inside evaluator.py's np.array reshape.
        assert len(features) == len(FEATURE_NAMES), (
            f"_compute_features() returned {len(features)} values but "
            f"FEATURE_NAMES has {len(FEATURE_NAMES)} entries — these must "
            f"match exactly. Check for a missing/extra line above."
        )

        return features


# Keep old name as an alias so existing imports don't break
PackerParser = PacketParser