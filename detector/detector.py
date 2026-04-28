import asyncio
import logging
from collections import deque
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class LogEntry:
    """Define the expected structure of a log entry"""
    source_ip: str
    status: int
    timestamp: datetime


class Detector:
    def __init__(self, config: dict, baseline_engine, unbanner, notifier, audit_log_func):
        self.config = config

        required_configs = [
            'sliding_window_seconds',
            'z_score_threshold',
            'rate_multiplier_threshold'
        ]

        for required in required_configs:
            if required not in config:
                raise ValueError(f"Missing required config: {required}")

        self.sliding_window_seconds = config['sliding_window_seconds']
        self.z_score_threshold = config['z_score_threshold']
        self.rate_multiplier_threshold = config['rate_multiplier_threshold']

        self.min_requests_for_anomaly = config.get('min_requests_for_anomaly', 5)
        self.max_ip_windows_size = config.get('max_ip_windows_size', 10000)
        self.ip_cleanup_interval_seconds = config.get('ip_cleanup_interval_seconds', 300)
        
        self.baseline_engine = baseline_engine
        self.unbanner = unbanner
        self.notifier = notifier
        self.audit_log_func = audit_log_func  # Fix 9: Renamed to avoid confusion

        self.ip_windows: Dict[str, deque] = {}
        self.global_window: deque = deque()
        self.blocked_ips: set = set()
        self._lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None

        self.blocker = None  # Will be set later


    def set_blocker(self, blocker):
        """Set blocker after initialization to avoid circular dependency"""
        self.blocker = blocker


    async def start(self):
        """Start the detector with cleanup task"""
        self._cleanup_task = asyncio.create_task(self._periodic_cleanup())
        logger.info("Detector started")


    async def stop(self):
        """Stop the detector and cleanup"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        logger.info("Detector stopped")


    async def _periodic_cleanup(self):
        """Fix 4: Periodic cleanup of old IP windows"""
        while True:
            try:
                await asyncio.sleep(self.ip_cleanup_interval_seconds)
                await self.cleanup_inactive_ips()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in periodic cleanup: {e}")


    async def cleanup_inactive_ips(self):
        """Fix 6: Remove IPs that haven't been active recently"""
        async with self._lock:
            cutoff = datetime.now() - timedelta(seconds=self.sliding_window_seconds * 2)
            inactive_ips = []

            for ip, window in self.ip_windows.items():
                if not window or window[-1]['ts'] < cutoff:
                    inactive_ips.append(ip)

            for ip in inactive_ips:
                del self.ip_windows[ip]
                logger.debug(f"Removed inactive IP: {ip}")

            if inactive_ips:
                logger.debug(f"Cleaned up {len(inactive_ips)} inactive IPs")


    async def process_request(self, entry: Any) -> None:
        """Fix 2: Process a single log entry with validation"""
        # Validate entry
        if not hasattr(entry, 'source_ip') or not hasattr(entry, 'status'):
            logger.warning(f"Invalid log entry format: {entry}")
            return

        if not entry.source_ip:
            logger.debug("Skipping entry with no source IP")
            return

        try:
            async with self._lock:
                now = datetime.now()

                if entry.source_ip not in self.ip_windows:
                    # Fix 6: Check max size before creating new IP
                    if len(self.ip_windows) >= self.max_ip_windows_size:
                        logger.warning(f"Max IP windows size reached, cleaning up...")
                        await self.cleanup_inactive_ips()

                    self.ip_windows[entry.source_ip] = deque()

                # Add to IP window
                self.ip_windows[entry.source_ip].append({
                    'ts': now,
                    'status': entry.status
                })

                while (self.ip_windows[entry.source_ip] and 
                       (now - self.ip_windows[entry.source_ip][0]['ts']).total_seconds() > self.sliding_window_seconds):
                    self.ip_windows[entry.source_ip].popleft()

                self.global_window.append(now)

                while (self.global_window and 
                       (now - self.global_window[0]).total_seconds() > self.sliding_window_seconds):
                    self.global_window.popleft()

                try:
                    await self.baseline_engine.add_request(entry.source_ip, now)
                except Exception as e:
                    logger.error(f"Failed to add request to baseline: {e}")
                    return

            await self.check_anomalies(entry.source_ip)

        except Exception as e:
            logger.error(f"Error processing request from {entry.source_ip}: {e}")


    async def check_anomalies(self, ip: str) -> None:
        """Check for anomalies for a specific IP and globally"""
        try:
            if not self.blocker:
                logger.error("Blocker not set in detector")
                return

            async with self._lock:
                # Check if IP is already blocked
                if ip in self.blocked_ips:
                    return

                # Get IP rate
                if ip not in self.ip_windows:
                    return

                ip_window = self.ip_windows[ip]
                if len(ip_window) < self.min_requests_for_anomaly:
                    return  # Not enough data

                ip_rate = len(ip_window) / self.sliding_window_seconds

                # Get global rate
                global_rate = len(self.global_window) / self.sliding_window_seconds

            try:
                mean, stddev = await self.baseline_engine.get_baseline()
            except Exception as e:
                logger.error(f"Failed to get baseline: {e}")
                return

            # Check IP anomaly
            is_ip_anomaly = False
            z_score = 0

            if mean > 0 and stddev > 0:
                z_score = (ip_rate - mean) / stddev
                is_ip_anomaly = (abs(z_score) > self.z_score_threshold or 
                                ip_rate > mean * self.rate_multiplier_threshold)
            elif mean > 0:
                is_ip_anomaly = ip_rate > mean * self.rate_multiplier_threshold

            if is_ip_anomaly:
                async with self._lock:
                    if ip not in self.blocked_ips:  # Double-check after lock
                        self.blocked_ips.add(ip)

                # Get ban duration from config
                ban_duration = self.config.get('initial_ban_duration', "10m")

                # Block the IP
                try:
                    if await self.blocker.block_ip(ip):
                        # Send notification
                        await self.notifier.send_ban_alert(
                            ip, ip_rate, mean, f"z={z_score:.2f}", ban_duration
                        )

                        # Audit log
                        if self.audit_log_func:
                            self.audit_log_func(
                                f"BAN ip={ip} rate={ip_rate:.2f} baseline={mean:.2f} z={z_score:.2f}"
                            )

                        # Schedule unban
                        await self.unbanner.schedule_unban(ip, ban_duration)

                        logger.info(f"Blocked anomalous IP: {ip} (rate={ip_rate:.2f}, baseline={mean:.2f})")
                except Exception as e:
                    logger.error(f"Failed to block IP {ip}: {e}")
                    async with self._lock:
                        self.blocked_ips.discard(ip)

            global_rate = len(self.global_window) / self.sliding_window_seconds

            is_global_anomaly = False
            if mean > 0 and stddev > 0:
                global_z_score = (global_rate - mean) / stddev
                is_global_anomaly = (abs(global_z_score) > self.z_score_threshold or 
                                    global_rate > mean * self.rate_multiplier_threshold)

            if is_global_anomaly:
                try:
                    await self.notifier.send_global_alert(global_rate, mean, f"z={global_z_score:.2f}")
                    if self.audit_log_func:
                        self.audit_log_func(
                            f"GLOBAL_ALERT rate={global_rate:.2f} baseline={mean:.2f} z={global_z_score:.2f}"
                        )
                    logger.warning(f"Global anomaly detected: rate={global_rate:.2f}, baseline={mean:.2f}")
                except Exception as e:
                    logger.error(f"Failed to send global alert: {e}")

        except Exception as e:
            logger.error(f"Error checking anomalies for IP {ip}: {e}")


    async def get_ip_rate(self, ip: str) -> float:
        """Get current rate for a specific IP"""
        async with self._lock:
            if ip not in self.ip_windows:
                return 0.0
            return len(self.ip_windows[ip]) / self.sliding_window_seconds


    async def get_global_rate(self) -> float:
        """Get current global rate"""
        async with self._lock:
            return len(self.global_window) / self.sliding_window_seconds


    async def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics"""
        async with self._lock:
            return {
                'total_ips_tracked': len(self.ip_windows),
                'blocked_ips_count': len(self.blocked_ips),
                'global_window_size': len(self.global_window),
                'global_rate': len(self.global_window) / self.sliding_window_seconds if self.global_window else 0,
                'config': {
                    'sliding_window_seconds': self.sliding_window_seconds,
                    'z_score_threshold': self.z_score_threshold,
                    'rate_multiplier_threshold': self.rate_multiplier_threshold,
                    'min_requests_for_anomaly': self.min_requests_for_anomaly
                }
            }
