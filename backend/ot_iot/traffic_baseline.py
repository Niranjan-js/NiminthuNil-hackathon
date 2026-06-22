"""
NIRAVAN Cyber Defense Operating System
OT/IoT Defense Layer — Traffic Baseline Module

Simulates learning normal traffic patterns per device and flags deviations
using statistical z-score analysis (sigma-based anomaly detection).
"""

import logging
import random
import math
import hashlib
from datetime import datetime, timedelta
from typing import Optional
from collections import defaultdict

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class TrafficBaseline:
    """
    Establishes and maintains per-device traffic baselines for OT/IoT assets.
    Uses statistical deviation (sigma scoring) to detect anomalies in live traffic.

    Attributes:
        _baselines (dict): Stores baseline profiles keyed by device_id.
        ANOMALY_SIGMA (float): Z-score threshold above which traffic is anomalous.
    """

    ANOMALY_SIGMA: float = 3.0

    # Realistic destination IP pools per device type
    _DEST_IP_POOLS: dict = {
        "PLC":             ["10.0.10.1", "10.0.10.5", "192.168.100.20", "10.0.20.50"],
        "CCTV_Camera":     ["192.168.1.200", "10.10.5.50", "58.182.12.44", "185.23.10.7"],
        "IP_Phone":        ["10.0.0.2", "172.16.5.10", "8.8.8.8", "1.1.1.1", "172.16.5.20"],
        "Printer":         ["192.168.1.1", "10.0.0.1", "192.168.1.100"],
        "Biometric":       ["10.1.1.5", "10.1.1.6", "172.16.0.50"],
        "Smart_Meter":     ["192.168.200.1", "10.20.30.1", "203.0.113.10"],
        "Raspberry_Pi":    ["8.8.8.8", "1.1.1.1", "104.18.10.100", "172.217.0.0"],
        "Smart_TV":        ["52.94.225.1", "13.226.202.10", "185.9.0.1", "104.244.42.1"],
        "HVAC_Controller": ["10.0.50.1", "10.0.50.2", "192.168.10.254"],
        "default":         ["10.0.0.1", "10.0.0.2", "8.8.8.8"],
    }

    _PROTOCOL_POOLS: dict = {
        "PLC":             ["Modbus/TCP", "DNP3", "EtherNet/IP", "PROFINET"],
        "CCTV_Camera":     ["RTSP", "HTTP", "HTTPS", "ONVIF"],
        "IP_Phone":        ["SIP", "RTP", "SRTP", "H.323"],
        "Printer":         ["IPP", "LPD", "SMB", "HTTP"],
        "Biometric":       ["TCP", "OSDP", "HTTP"],
        "Smart_Meter":     ["DLMS/COSEM", "ANSI C12.22", "IEC 62056", "UDP"],
        "Raspberry_Pi":    ["SSH", "HTTP", "HTTPS", "MQTT", "TCP"],
        "Smart_TV":        ["HTTPS", "HTTP", "SSDP", "mDNS", "DIAL"],
        "HVAC_Controller": ["BACnet/IP", "Modbus/TCP", "SNMP", "HTTP"],
        "default":         ["TCP", "UDP", "HTTP"],
    }

    _PORT_POOLS: dict = {
        "PLC":             [502, 20000, 44818, 2404, 47808],
        "CCTV_Camera":     [554, 80, 443, 8080, 8554],
        "IP_Phone":        [5060, 5061, 16384, 32767, 443],
        "Printer":         [631, 515, 9100, 445, 80],
        "Biometric":       [80, 443, 4370],
        "Smart_Meter":     [4059, 1153, 8080, 61450],
        "Raspberry_Pi":    [22, 80, 443, 1883, 8883, 8080],
        "Smart_TV":        [443, 80, 1900, 5353, 8008],
        "HVAC_Controller": [47808, 502, 161, 80, 443],
        "default":         [80, 443, 8080],
    }

    _BYTES_PER_MIN_DEFAULTS: dict = {
        "PLC":             (200.0, 40.0),
        "CCTV_Camera":     (15000.0, 2500.0),
        "IP_Phone":        (3500.0, 600.0),
        "Printer":         (800.0, 150.0),
        "Biometric":       (120.0, 25.0),
        "Smart_Meter":     (90.0, 18.0),
        "Raspberry_Pi":    (2500.0, 500.0),
        "Smart_TV":        (12000.0, 3000.0),
        "HVAC_Controller": (300.0, 60.0),
        "default":         (500.0, 100.0),
    }

    _CONNECTIONS_PER_HOUR_DEFAULTS: dict = {
        "PLC":             (12.0, 3.0),
        "CCTV_Camera":     (8.0, 2.0),
        "IP_Phone":        (30.0, 8.0),
        "Printer":         (15.0, 5.0),
        "Biometric":       (5.0, 1.5),
        "Smart_Meter":     (4.0, 1.0),
        "Raspberry_Pi":    (40.0, 10.0),
        "Smart_TV":        (25.0, 6.0),
        "HVAC_Controller": (6.0, 2.0),
        "default":         (20.0, 5.0),
    }

    def __init__(self) -> None:
        """Initialise empty baselines store."""
        self._baselines: dict = {}
        logger.info("TrafficBaseline engine initialised.")

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def establish_baseline(
        self,
        device_id: str,
        device_type: str,
        observation_hours: int = 24,
    ) -> dict:
        """
        Simulate learning a device's normal traffic behaviour over *observation_hours*.

        The method generates statistically realistic baseline metrics for the
        given device type and persists them in ``_baselines``.

        Args:
            device_id: Unique identifier for the OT/IoT device.
            device_type: Canonical device category (e.g. 'PLC', 'CCTV_Camera').
            observation_hours: Number of hours of traffic observation to simulate.

        Returns:
            A dictionary containing the full baseline profile.
        """
        logger.info(
            "Establishing baseline for device=%s type=%s hours=%d",
            device_id, device_type, observation_hours,
        )

        bpm_mean, bpm_std = self._BYTES_PER_MIN_DEFAULTS.get(
            device_type, self._BYTES_PER_MIN_DEFAULTS["default"]
        )
        cph_mean, cph_std = self._CONNECTIONS_PER_HOUR_DEFAULTS.get(
            device_type, self._CONNECTIONS_PER_HOUR_DEFAULTS["default"]
        )

        # Simulate observation variance slightly around the mean
        observed_bpm_mean = bpm_mean + random.uniform(-bpm_mean * 0.05, bpm_mean * 0.05)
        observed_bpm_std  = bpm_std  + random.uniform(-bpm_std  * 0.10, bpm_std  * 0.10)
        observed_cph_mean = cph_mean + random.uniform(-cph_mean * 0.05, cph_mean * 0.05)

        dest_pool       = self._DEST_IP_POOLS.get(device_type, self._DEST_IP_POOLS["default"])
        protocol_pool   = self._PROTOCOL_POOLS.get(device_type, self._PROTOCOL_POOLS["default"])
        port_pool       = self._PORT_POOLS.get(device_type, self._PORT_POOLS["default"])

        num_top_dests   = min(len(dest_pool), random.randint(2, max(2, len(dest_pool) - 1)))
        top_destinations = random.sample(dest_pool, num_top_dests)

        unique_dest_mean = float(num_top_dests) + random.uniform(0.0, 1.5)

        now = datetime.utcnow()
        baseline = {
            "device_id":      device_id,
            "device_type":    device_type,
            "established_at": now.isoformat() + "Z",
            "observation_window_hours": observation_hours,
            "sample_count":   observation_hours * 60,
            "metrics": {
                "bytes_per_min_mean":         round(observed_bpm_mean, 4),
                "bytes_per_min_std":          round(max(1.0, observed_bpm_std), 4),
                "connections_per_hour_mean":  round(observed_cph_mean, 4),
                "connections_per_hour_std":   round(max(0.5, cph_std), 4),
                "unique_destinations_mean":   round(unique_dest_mean, 4),
                "unique_destinations_std":    round(random.uniform(0.3, 1.2), 4),
                "top_destinations":           top_destinations,
                "typical_protocols":          protocol_pool,
                "typical_ports":              port_pool,
                "avg_packet_size_bytes_mean": round(random.uniform(64.0, 1400.0), 2),
                "avg_packet_size_bytes_std":  round(random.uniform(10.0, 200.0), 2),
                "inter_connection_interval_s_mean": round(random.uniform(5.0, 300.0), 2),
                "inter_connection_interval_s_std":  round(random.uniform(1.0, 60.0), 2),
            },
            "hash": self._fingerprint(device_id, device_type, now.isoformat()),
        }

        self._baselines[device_id] = baseline
        logger.debug("Baseline stored for device_id=%s", device_id)
        return baseline

    def check_deviation(self, device_id: str, current_metrics: dict) -> dict:
        """
        Compare *current_metrics* against the stored baseline for *device_id*.

        Computes a z-score (sigma) for each numeric metric and flags the device
        as anomalous if any sigma exceeds ``ANOMALY_SIGMA``.

        Args:
            device_id: The device whose baseline to compare against.
            current_metrics: Live metrics dictionary with the same keys as
                             ``baseline["metrics"]``.

        Returns:
            Detection result dictionary with deviations list, sigma score,
            anomaly flag, and confidence estimate.
        """
        now = datetime.utcnow()
        if device_id not in self._baselines:
            logger.warning("No baseline found for device_id=%s", device_id)
            return {
                "device_id": device_id,
                "timestamp": now.isoformat() + "Z",
                "error": "No baseline established for this device.",
                "deviations": [],
                "sigma_score": 0.0,
                "is_anomalous": False,
                "confidence": 0.0,
                "anomaly_details": [],
            }

        baseline_metrics = self._baselines[device_id]["metrics"]
        deviations: list = []
        anomaly_details: list = []
        sigma_scores: list = []

        numeric_pairs = [
            ("bytes_per_min",        "bytes_per_min_mean",        "bytes_per_min_std"),
            ("connections_per_hour", "connections_per_hour_mean",  "connections_per_hour_std"),
            ("unique_destinations",  "unique_destinations_mean",   "unique_destinations_std"),
            ("avg_packet_size_bytes","avg_packet_size_bytes_mean", "avg_packet_size_bytes_std"),
        ]

        for field, mean_key, std_key in numeric_pairs:
            if field not in current_metrics:
                continue
            observed = float(current_metrics[field])
            mean_val = float(baseline_metrics.get(mean_key, 0))
            std_val  = float(baseline_metrics.get(std_key, 1))
            if std_val < 1e-9:
                std_val = 1e-9
            sigma = abs(observed - mean_val) / std_val
            sigma_scores.append(sigma)

            if sigma >= self.ANOMALY_SIGMA:
                direction = "above" if observed > mean_val else "below"
                deviations.append(field)
                anomaly_details.append({
                    "metric":        field,
                    "observed":      observed,
                    "baseline_mean": mean_val,
                    "baseline_std":  std_val,
                    "sigma":         round(sigma, 4),
                    "direction":     direction,
                    "severity":      self._sigma_to_severity(sigma),
                })
                logger.debug(
                    "Deviation detected: field=%s sigma=%.2f observed=%.2f mean=%.2f",
                    field, sigma, observed, mean_val,
                )

        # Check for new protocols / ports
        current_protocols = set(current_metrics.get("protocols", []))
        baseline_protocols = set(baseline_metrics.get("typical_protocols", []))
        unknown_protocols = current_protocols - baseline_protocols
        if unknown_protocols:
            deviations.append("unexpected_protocols")
            anomaly_details.append({
                "metric":   "protocols",
                "observed": list(unknown_protocols),
                "baseline": list(baseline_protocols),
                "sigma":    self.ANOMALY_SIGMA + 0.5,
                "severity": "HIGH",
            })

        current_ports = set(current_metrics.get("ports", []))
        baseline_ports = set(baseline_metrics.get("typical_ports", []))
        unknown_ports = current_ports - baseline_ports
        if unknown_ports:
            deviations.append("unexpected_ports")
            anomaly_details.append({
                "metric":   "ports",
                "observed": list(unknown_ports),
                "baseline": list(baseline_ports),
                "sigma":    self.ANOMALY_SIGMA + 1.0,
                "severity": "HIGH",
            })

        # Check new destinations
        current_dests = set(current_metrics.get("destinations", []))
        baseline_dests = set(baseline_metrics.get("top_destinations", []))
        new_dests = current_dests - baseline_dests
        if new_dests:
            deviations.append("new_destinations")
            anomaly_details.append({
                "metric":   "destinations",
                "new_ips":  list(new_dests),
                "baseline": list(baseline_dests),
                "sigma":    self.ANOMALY_SIGMA,
                "severity": "MEDIUM",
            })

        max_sigma    = max(sigma_scores, default=0.0)
        is_anomalous = bool(deviations)
        confidence   = self._compute_confidence(sigma_scores, len(deviations))

        result = {
            "device_id":      device_id,
            "device_type":    self._baselines[device_id].get("device_type", "unknown"),
            "timestamp":      now.isoformat() + "Z",
            "deviations":     deviations,
            "sigma_score":    round(max_sigma, 4),
            "is_anomalous":   is_anomalous,
            "confidence":     round(confidence, 4),
            "anomaly_details": anomaly_details,
            "baseline_established_at": self._baselines[device_id].get("established_at"),
        }
        logger.info(
            "Deviation check complete: device=%s is_anomalous=%s sigma=%.2f",
            device_id, is_anomalous, max_sigma,
        )
        return result

    def update_baseline(self, device_id: str, new_metrics: dict) -> None:
        """
        Incrementally update the stored baseline for *device_id* using
        exponential moving average (alpha = 0.1).

        Args:
            device_id: Target device identifier.
            new_metrics: Fresh observation dict (same schema as baseline metrics).
        """
        if device_id not in self._baselines:
            logger.warning(
                "update_baseline called for unknown device_id=%s — ignored.", device_id
            )
            return

        alpha = 0.10
        bm = self._baselines[device_id]["metrics"]

        numeric_pairs = [
            ("bytes_per_min",         "bytes_per_min_mean",        "bytes_per_min_std"),
            ("connections_per_hour",  "connections_per_hour_mean",  "connections_per_hour_std"),
            ("unique_destinations",   "unique_destinations_mean",   "unique_destinations_std"),
            ("avg_packet_size_bytes", "avg_packet_size_bytes_mean", "avg_packet_size_bytes_std"),
        ]

        for field, mean_key, std_key in numeric_pairs:
            if field not in new_metrics:
                continue
            observed = float(new_metrics[field])
            old_mean = float(bm.get(mean_key, observed))
            old_std  = float(bm.get(std_key, 1.0))

            new_mean = alpha * observed + (1 - alpha) * old_mean
            new_std  = math.sqrt(
                alpha * (observed - new_mean) ** 2 + (1 - alpha) * old_std ** 2
            )
            bm[mean_key] = round(new_mean, 4)
            bm[std_key]  = round(max(1.0, new_std), 4)

        self._baselines[device_id]["last_updated"] = datetime.utcnow().isoformat() + "Z"
        logger.info("Baseline updated (EMA) for device_id=%s", device_id)

    def get_all_baselines(self) -> list:
        """
        Return a list of all stored baseline profiles.

        Returns:
            List of baseline dictionaries.
        """
        baselines_list = list(self._baselines.values())
        logger.debug("get_all_baselines: returning %d entries.", len(baselines_list))
        return baselines_list

    def export_baseline_report(self) -> dict:
        """
        Generate a full report of all baselines including summary statistics.

        Returns:
            Report dictionary with metadata, per-device summaries, and
            aggregate statistics.
        """
        now = datetime.utcnow()
        device_summaries = []
        total_bpm = []

        for device_id, bl in self._baselines.items():
            metrics = bl.get("metrics", {})
            bpm     = metrics.get("bytes_per_min_mean", 0.0)
            total_bpm.append(bpm)
            device_summaries.append({
                "device_id":              device_id,
                "device_type":            bl.get("device_type"),
                "established_at":         bl.get("established_at"),
                "last_updated":           bl.get("last_updated"),
                "bytes_per_min_mean":     bpm,
                "connections_per_hour":   metrics.get("connections_per_hour_mean", 0.0),
                "unique_destinations":    metrics.get("unique_destinations_mean", 0.0),
                "typical_protocols":      metrics.get("typical_protocols", []),
                "observation_window_hrs": bl.get("observation_window_hours", 24),
                "hash":                   bl.get("hash"),
            })

        avg_bpm = (sum(total_bpm) / len(total_bpm)) if total_bpm else 0.0

        report = {
            "report_id":         self._fingerprint("export", now.isoformat(), "report"),
            "generated_at":      now.isoformat() + "Z",
            "engine":            "NIRAVAN TrafficBaseline v2.4",
            "anomaly_threshold": self.ANOMALY_SIGMA,
            "total_devices":     len(self._baselines),
            "device_summaries":  device_summaries,
            "aggregate_stats": {
                "avg_bytes_per_min_across_devices": round(avg_bpm, 4),
                "total_baselines_established":      len(self._baselines),
            },
            "signature": hashlib.sha256(
                f"niravan-baseline-{now.isoformat()}".encode()
            ).hexdigest(),
        }
        logger.info("Baseline export report generated: %d devices.", len(self._baselines))
        return report

    # ------------------------------------------------------------------ #
    #  Private helpers                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _sigma_to_severity(sigma: float) -> str:
        """Map a sigma value to a human-readable severity label."""
        if sigma >= 6.0:
            return "CRITICAL"
        if sigma >= 4.5:
            return "HIGH"
        if sigma >= 3.0:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _compute_confidence(sigma_scores: list, deviation_count: int) -> float:
        """
        Estimate detection confidence [0..1] based on sigma scores and
        number of deviating metrics.
        """
        if not sigma_scores and deviation_count == 0:
            return 0.0
        base = min(1.0, deviation_count / 5.0)
        max_s = max(sigma_scores, default=0.0)
        sigma_contrib = min(1.0, max_s / 10.0)
        return round(0.5 * base + 0.5 * sigma_contrib, 4)

    @staticmethod
    def _fingerprint(device_id: str, device_type: str, ts: str) -> str:
        """Generate a deterministic SHA-256 fingerprint for a baseline."""
        raw = f"{device_id}:{device_type}:{ts}"
        return hashlib.sha256(raw.encode()).hexdigest()
