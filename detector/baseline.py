import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Tuple, Dict, Optional
import math

logger = logging.getLogger(__name__)


class BaselineEngine:
    def __init__(self, config: dict):
        self.config = config


        required_configs = [
            'baseline_window_minutes',
            'baseline_recalc_interval_seconds',
            'z_score_threshold',
            'rate_multiplier_threshold'
        ]

        for required in required_configs:
            if required not in config:
                raise ValueError(f"Missing required config: {required}")

        self.baseline_window_minutes = config['baseline_window_minutes']
        self.baseline_recalc_interval_seconds = config['baseline_recalc_interval_seconds']
        self.z_score_threshold = config['z_score_threshold']
        self.rate_multiplier_threshold = config['rate_multiplier_threshold']

        # Optional configs with validation instead of hardcoded defaults
        self.min_data_points_for_baseline = config.get('min_data_points_for_baseline')
        if self.min_data_points_for_baseline is None:
            raise ValueError("Missing required config: min_data_points_for_baseline")

        self.data_retention_hours = config.get('data_retention_hours')
        if self.data_retention_hours is None:
            raise ValueError("Missing required config: data_retention_hours")

        self.max_data_points = config.get('max_data_points')
        if self.max_data_points is None:
            raise ValueError("Missing required config: max_data_points")

        # Initialize data structures
        self.per_second_counts: Dict[int, Dict[str, int]] = {}
        self.global_counts: Dict[int, int] = {}


        self.current_mean = None
        self.current_stddev = None
        self.is_initialized = False

        self._lock = asyncio.Lock()
        self.running = False
        self._stop_event = asyncio.Event()


    async def start(self):
        """Start the baseline engine"""
        logger.info("Baseline engine started")
        self.running = True

        # Perform initial calculation
        await self.recalculate()

        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(), 
                    timeout=self.baseline_recalc_interval_seconds
                )
                break
            except asyncio.TimeoutError:
                await self.recalculate()
                await self.clean_old_data()


    async def stop(self):
        """Graceful shutdown method"""
        logger.info("Stopping baseline engine...")
        self._stop_event.set()
        self.running = False
        await asyncio.sleep(0.5)
        logger.info("Baseline engine stopped")


    async def add_request(self, ip: str, timestamp: datetime):
        """Add a request to the baseline data"""
        async with self._lock:
            ts = int(timestamp.timestamp())

            if ts not in self.per_second_counts:
                self.per_second_counts[ts] = {}

            self.per_second_counts[ts][ip] = self.per_second_counts[ts].get(ip, 0) + 1
            self.global_counts[ts] = self.global_counts.get(ts, 0) + 1

            # Trim data if exceeding max size
            if len(self.global_counts) > self.max_data_points:
                oldest_ts = min(self.global_counts.keys())
                self._trim_data_upto(oldest_ts + 100)


    def _trim_data_upto(self, timestamp: int):
        """Helper method to trim old data"""
        self.per_second_counts = {
            ts: v for ts, v in self.per_second_counts.items() 
            if ts >= timestamp
        }
        self.global_counts = {
            ts: v for ts, v in self.global_counts.items() 
            if ts >= timestamp
        }


    async def recalculate(self):
        """Recalculate baseline statistics"""
        async with self._lock:
            now = datetime.now()
            window_start = now - timedelta(minutes=self.baseline_window_minutes)

            rates = []
            start_ts = int(window_start.timestamp())
            end_ts = int(now.timestamp())

            for ts in range(start_ts, end_ts):
                if ts in self.global_counts:
                    rates.append(float(self.global_counts[ts]))

            if len(rates) < self.min_data_points_for_baseline:
                if not self.is_initialized:
                    logger.warning(f"Insufficient data for baseline initialization. "
                                 f"Have {len(rates)}, need {self.min_data_points_for_baseline}. "
                                 f"Waiting for more data...")
                return

            # Calculate new mean and standard deviation
            new_mean = sum(rates) / len(rates)

            if len(rates) > 1:
                variance = sum((x - new_mean) ** 2 for x in rates) / len(rates)
                new_stddev = math.sqrt(variance)
            else:
                new_stddev = 0.0

            # Update values
            old_mean = self.current_mean
            old_stddev = self.current_stddev
            self.current_mean = new_mean
            self.current_stddev = new_stddev
            self.is_initialized = True

            # Log if this is first initialization or significant change
            if old_mean is None:
                logger.info(f"Baseline initialized: mean={self.current_mean:.2f}, "
                          f"stddev={self.current_stddev:.2f}, samples={len(rates)}")
            elif old_mean > 0:
                mean_change = abs(self.current_mean - old_mean) / old_mean
                if mean_change > self.config.get('significant_change_threshold', 0.5):
                    logger.warning(f"Baseline mean changed significantly: "
                                 f"{old_mean:.2f} -> {self.current_mean:.2f} "
                                 f"({mean_change:.1%})")

            logger.debug(f"Baseline updated: mean={self.current_mean:.2f}, "
                        f"stddev={self.current_stddev:.2f}, samples={len(rates)}")


    async def clean_old_data(self):
        """Clean data older than retention period"""
        async with self._lock:
            cutoff = int((datetime.now() - timedelta(hours=self.data_retention_hours)).timestamp())

            old_count = len(self.global_counts)
            self._trim_data_upto(cutoff)
            new_count = len(self.global_counts)

            if old_count > new_count:
                logger.debug(f"Cleaned {old_count - new_count} old data points")


    async def get_baseline(self) -> Tuple[float, float]:
        """Get current baseline statistics"""
        async with self._lock:
            if not self.is_initialized:
                raise ValueError("Baseline not yet initialized. Insufficient data.")
            return self.current_mean, self.current_stddev


    async def get_z_score(self, current_rate: float) -> Optional[float]:
        """Calculate z-score for current rate"""
        async with self._lock:
            if not self.is_initialized:
                return None
            if self.current_stddev and self.current_stddev > 0:
                return (current_rate - self.current_mean) / self.current_stddev
            return None


    async def is_anomaly(self, current_rate: float, ip_rate: Optional[float] = None) -> bool:
        """Check if current rate is anomalous"""
        async with self._lock:
            if not self.is_initialized:
                logger.debug("Baseline not initialized, cannot detect anomalies")
                return False

            # Check global z-score
            if self.current_stddev and self.current_stddev > 0:
                z_score = abs((current_rate - self.current_mean) / self.current_stddev)
                if z_score > self.z_score_threshold:
                    logger.debug(f"Anomaly detected: z-score={z_score:.2f}")
                    return True

            # Check rate multiplier for IP-specific anomalies
            if ip_rate is not None and self.current_mean and self.current_mean > 0:
                multiplier = ip_rate / self.current_mean
                if multiplier > self.rate_multiplier_threshold:
                    logger.debug(f"Rate multiplier anomaly: {multiplier:.2f}x baseline")
                    return True

            return False


    async def get_stats(self) -> Dict:
        """Get detailed statistics for debugging"""
        async with self._lock:
            stats = {
                'is_initialized': self.is_initialized,
                'data_points': len(self.global_counts),
                'unique_seconds': len(self.per_second_counts),
                'config': {
                    'baseline_window_minutes': self.baseline_window_minutes,
                    'baseline_recalc_interval_seconds': self.baseline_recalc_interval_seconds,
                    'z_score_threshold': self.z_score_threshold,
                    'rate_multiplier_threshold': self.rate_multiplier_threshold,
                    'min_data_points_for_baseline': self.min_data_points_for_baseline,
                    'data_retention_hours': self.data_retention_hours,
                    'max_data_points': self.max_data_points
                }
            }

            if self.is_initialized:
                stats.update({
                    'mean': self.current_mean,
                    'stddev': self.current_stddev,
                    'oldest_timestamp': min(self.global_counts.keys()) if self.global_counts else None,
                    'newest_timestamp': max(self.global_counts.keys()) if self.global_counts else None,
                })

            return stats


    async def __aenter__(self):
        await self.start()
        return self


    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()
