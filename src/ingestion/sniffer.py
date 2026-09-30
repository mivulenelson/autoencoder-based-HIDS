"""
src/ingestion/sniffer.py
------------------------
Real-time packet capture engine for the Autoencoder HIDS.

Implements a multi-threaded producer-consumer pattern (proposal §3.2.1):
  - Sniffer thread  : Scapy `sniff()` captures raw packets → Queue (producer)
  - Worker thread   : Dequeues packets → PacketParser → (features, meta) → callback

The callback forwards feature vectors to the FastAPI detection route, which
feeds them into DetectionEvaluator for anomaly scoring. `meta` carries the
real src_ip/dst_ip/protocol/is_encrypted for that exact flow (see parser.py).

Environment variables (set in .env):
    SNIFFER_INTERFACE   Network interface to monitor  (default: wlo1)
    MAX_BUFFER_SIZE     Packet queue depth             (default: 2000)

BUG FIXED — real IP addresses never reached the GUI
-----------------------------------------------------
parser.py's parse_to_features()/flush() now return (features, flow_meta)
tuples instead of a bare feature list. This file's _worker_loop(), _dispatch(),
and the standalone smoke-test callback are updated to unpack and forward both
values through on_feature_extracted(features, meta).

This also makes MonitorService's previous packet-interceptor monkey-patch
(`sniffer._packet_callback = ...`) unnecessary — it never worked in the first
place (HIDSSniffer has no such attribute; Scapy's callback is hardcoded as
prn=self._enqueue_packet), and even if it had, it would have attributed
alerts to whichever packet arrived most recently rather than the specific
flow that triggered the alert. Now the real IP/port/protocol travels with
the exact flow that produced it, with no separate tracking needed.

IMPROVEMENTS — tied to eda_encrypted_subset.ipynb / training_validated.ipynb
------------------------------------------------------------------------------
1. NEW: _log_flow() now tags encrypted (TLS/HTTPS-class) flows in the
   console log, using the SAME ENCRYPTED_PORTS set eda_encrypted_subset.ipynb
   uses to isolate the encrypted subset for analysis — imported directly
   from parser.py rather than duplicated here, so there is exactly one
   source of truth for what counts as "encrypted" across notebooks and
   the live system.
2. The standalone smoke-test callback now prints meta["is_encrypted"] so
   the new field is visible immediately when testing this file directly.
3. Comment references to "training.ipynb" updated to
   "training_validated.ipynb" for consistency with the rest of the project.
"""

import os
import logging
import time
from threading import Thread, Event
from queue import Queue, Empty

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from dotenv import load_dotenv

from src.ingestion.parser import PacketParser, ENCRYPTED_PORTS

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("HIDS_Sniffer")

# Sentinel used to signal the worker thread to exit cleanly
_STOP_SENTINEL = object()


class HIDSSniffer:
    """
    Captures live network traffic from the host interface and emits 22-feature
    flow vectors (with real flow metadata) to a registered callback.

    Usage:
        def on_features(features: list, meta: dict):
            print(meta["src_ip"], meta["dst_ip"], meta["protocol"],
                  meta["is_encrypted"], features)

        sniffer = HIDSSniffer(interface="wlo1", on_feature_extracted=on_features)
        sniffer.start()
        ...
        sniffer.stop()
    """

    def __init__(
        self,
        interface: str | None = None,
        on_feature_extracted=None,
        min_flow_packets: int = 5,
    ):
        """
        Args:
            interface:             Network interface to sniff (e.g. wlo1, eth0).
                                   Falls back to SNIFFER_INTERFACE env var, then "wlo1".
            on_feature_extracted:  Callback receiving (features: list[float],
                                   meta: dict) for each completed flow. `meta`
                                   contains src_ip/dst_ip/src_port/dst_port/
                                   protocol/is_encrypted for that exact flow.
                                   Called from the worker thread — must be
                                   thread-safe.
            min_flow_packets:      Minimum packets before a flow is emitted (default 5,
                                   matching extract_22_features() in training_validated.ipynb).
        """
        self.interface = interface or os.getenv("SNIFFER_INTERFACE", "wlo1")
        self._queue    = Queue(maxsize=int(os.getenv("MAX_BUFFER_SIZE", 2000)))

        # min_flow_packets is stored so reset_parser() can rebuild an
        # identically-configured PacketParser after a hot-swap.
        self._min_flow_packets = min_flow_packets
        self._parser   = PacketParser(min_packets=min_flow_packets)

        self._stop_evt = Event()            # clean shutdown signal for sniff loop
        self.on_feature_extracted = on_feature_extracted

        self._sniffer_thread: Thread | None = None
        self._worker_thread:  Thread | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the sniffer and worker threads."""
        if self._sniffer_thread and self._sniffer_thread.is_alive():
            logger.warning("Sniffer is already running.")
            return

        self._stop_evt.clear()

        self._worker_thread = Thread(
            target=self._worker_loop, name="HIDS-Worker", daemon=True
        )
        self._worker_thread.start()

        self._sniffer_thread = Thread(
            target=self._sniff_loop, name="HIDS-Sniffer", daemon=True
        )
        self._sniffer_thread.start()

        logger.info(
            f"HIDS Engine Online — monitoring '{self.interface}' in promiscuous mode."
        )

    def stop(self, timeout: float = 5.0) -> None:
        """
        Signal both threads to stop and wait for clean shutdown.

        Args:
            timeout: Seconds to wait for each thread to join.
        """
        logger.info("Stopping HIDS sniffer...")
        self._stop_evt.set()

        # Flush any partial flows before shutdown — each item is now a
        # (features, meta) tuple, matching parse_to_features()'s return shape.
        leftover = self._parser.flush()
        for features, meta in leftover:
            self._dispatch(features, meta)

        # Unblock the worker queue so it can read the stop event
        try:
            self._queue.put_nowait(_STOP_SENTINEL)
        except Exception:
            pass

        if self._worker_thread:
            self._worker_thread.join(timeout=timeout)
        if self._sniffer_thread:
            self._sniffer_thread.join(timeout=timeout)

        logger.info("HIDS sniffer stopped.")

    def reset_parser(self) -> None:
        """
        Discards all in-progress flow state and starts fresh.

        Call this after switching network interfaces (see
        MonitorService.restart_with_new_interface()) — without it, partially
        accumulated packet counts / timestamps from the OLD interface's
        flows would still be sitting in the parser's active_flows dict and
        could get merged with packets from the NEW interface, producing
        corrupted feature vectors (e.g. a flow_duration spanning both
        interfaces, or a 5-tuple key collision).

        Safe to call whether or not the sniffer is currently running —
        it only touches the parser, not the capture threads.
        """
        old_flow_count = len(getattr(self._parser, "_flows", {}) or {})
        self._parser = PacketParser(min_packets=self._min_flow_packets)
        logger.info(
            f"Parser reset — discarded {old_flow_count} in-progress flow(s) "
            f"from the previous interface."
        )

    @property
    def is_running(self) -> bool:
        return (
            self._sniffer_thread is not None
            and self._sniffer_thread.is_alive()
        )

    @property
    def packet_queue(self) -> Queue:
        """
        Exposes the internal packet queue read-only for status widgets
        (e.g. IngestionPage buffer-occupancy display: sniffer.packet_queue.qsize()).
        """
        return self._queue

    # ------------------------------------------------------------------
    # Thread targets
    # ------------------------------------------------------------------

    def _sniff_loop(self) -> None:
        """
        Producer thread: Scapy sniff() → raw packets → _queue.

        'filter="ip"' instructs the kernel BPF to pass only IP packets,
        reducing userspace overhead.
        'store=0' prevents Scapy from accumulating packets in RAM.
        'stop_filter' polls the Event so the loop exits cleanly on stop().

        NOTE: filter="ip" (BPF) matches IPv4 only, consistent with
        PacketParser's IPv4-only haslayer(IP) check — see parser.py's
        class docstring for the disclosed IPv6 limitation.
        """
        logger.info(f"Sniff loop active on interface: {self.interface}")
        try:
            sniff(
                iface=self.interface,
                filter="ip",
                promisc=True,
                prn=self._enqueue_packet,
                store=0,
                stop_filter=lambda _: self._stop_evt.is_set(),
            )
        except Exception as exc:
            logger.error(f"Sniff loop error: {exc}")
            self._stop_evt.set()

    def _worker_loop(self) -> None:
        """
        Consumer thread: dequeues packets → PacketParser → (features, meta)
        → on_feature_extracted callback.
        """
        logger.info("Worker thread ready.")
        while not self._stop_evt.is_set():
            try:
                item = self._queue.get(timeout=1.0)
            except Empty:
                continue

            # Shutdown sentinel
            if item is _STOP_SENTINEL:
                self._queue.task_done()
                break

            packet = item
            try:
                result = self._parser.parse_to_features(packet)
                if result is not None:
                    features, meta = result
                    self._log_flow(packet, meta)
                    self._dispatch(features, meta)
            except Exception as exc:
                logger.error(f"Worker processing error: {exc}")
            finally:
                self._queue.task_done()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _enqueue_packet(self, packet) -> None:
        """
        Scapy prn callback — runs in the sniffer thread.
        Drops the packet silently if the queue is full (back-pressure).
        """
        if not packet.haslayer(IP):
            return
        try:
            self._queue.put_nowait(packet)
        except Exception:
            # Queue full — drop packet; this is acceptable for a real-time IDS
            pass

    def _dispatch(self, features: list, meta: dict) -> None:
        """
        Forward a 22-feature vector AND its real flow metadata to the
        registered callback. Both arguments are now required — meta carries
        src_ip/dst_ip/src_port/dst_port/protocol/is_encrypted for the exact
        flow that produced `features`.
        """
        if self.on_feature_extracted:
            try:
                self.on_feature_extracted(features, meta)
            except Exception as exc:
                logger.error(f"Feature callback error: {exc}")

    def _log_flow(self, packet, meta: dict) -> None:
        """
        Log source->destination metadata for console visibility (L3/L4 only).

        NEW: tags encrypted (TLS/HTTPS-class) flows using the same
        ENCRYPTED_PORTS heuristic eda_encrypted_subset.ipynb uses to isolate
        the encrypted subset — imported from parser.py, not duplicated here,
        so this stays in sync automatically if that set is ever revised.
        """
        try:
            ip   = packet[IP]
            proto = "UNKNOWN"
            sport = dport = 0
            if packet.haslayer(TCP):
                proto = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
            elif packet.haslayer(UDP):
                proto = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport

            enc_tag = " [TLS/ENCRYPTED]" if meta.get("is_encrypted") else ""
            logger.info(
                f"[Flow] {ip.src}:{sport} → {ip.dst}:{dport} ({proto}){enc_tag}"
            )
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Standalone smoke-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    def _mock_callback(features: list, meta: dict) -> None:
        from src.ingestion.parser import FEATURE_NAMES
        named = dict(zip(FEATURE_NAMES, features))
        enc_str = "ENCRYPTED" if meta.get("is_encrypted") else "plaintext"
        print(
            f"[MOCK API] {meta['src_ip']}:{meta['src_port']} -> "
            f"{meta['dst_ip']}:{meta['dst_port']} ({meta['protocol']}, {enc_str})"
        )
        print(f"           features: {named}")

    sniffer = HIDSSniffer(interface="wlo1", on_feature_extracted=_mock_callback)
    try:
        sniffer.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sniffer.stop()