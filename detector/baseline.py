# detector/baseline.py - FIXED VERSION

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Tuple
import math

logger = logging.getLogger(__name__)


class BaselineEngine:
    def __init__(self, config: dict):
        self.config = config
        self.per_second_counts = {}
        self.global_counts = {}
        self.current_mean = 10.0
        self.current_stddev = 5.0
        self.min_data_points = config.get('min_data_points_for_baseline', 10)
        self._lock = asyncio.Lock()
        self.running = False


    async def start(self):
        logger.info(f"Baseline engine started (min_data_points: {self.min_data_points})")
        self.running = True
        await self.recalculate()
        while self.running:
            await asyncio.sleep(self.config['baseline_recalc_interval_seconds'])
            await self.recalculate()
            await self.clean_old_data()


    async def add_request(self, ip: str, timestamp: datetime):
        async with self._lock:
            ts = int(timestamp.timestamp())
            if ts not in self.per_second_counts:
                self.per_second_counts[ts] = {}
            self.per_second_counts[ts][ip] = self.per_second_counts[ts].get(ip, 0) + 1
            self.global_counts[ts] = self.global_counts.get(ts, 0) + 1


    async def recalculate(self):
        async with self._lock:
            now = datetime.now()
            window_start = now - timedelta(minutes=self.config['baseline_window_minutes'])
            rates = []
            for ts in range(int(window_start.timestamp()), int(now.timestamp())):
                if ts in self.global_counts:
                    rates.append(float(self.global_counts[ts]))

            if len(rates) >= self.min_data_points:
                self.current_mean = sum(rates) / len(rates)
                if len(rates) > 1:
                    variance = sum((x - self.current_mean) ** 2 for x in rates) / len(rates)
                    self.current_stddev = math.sqrt(variance)
                logger.debug(f"Baseline updated: mean={self.current_mean:.2f}, stddev={self.current_stddev:.2f}, samples={len(rates)}")
            else:
                logger.debug(f"Insufficient data: {len(rates)} < {self.min_data_points}, using defaults")


    async def clean_old_data(self):
        async with self._lock:
            cutoff = int((datetime.now() - timedelta(hours=2)).timestamp())
            self.per_second_counts = {ts: v for ts, v in self.per_second_counts.items() if ts >= cutoff}
            self.global_counts = {ts: v for ts, v in self.global_counts.items() if ts >= cutoff}


    async def get_baseline(self) -> Tuple[float, float]:
        async with self._lock:
            return self.current_mean, self.current_stddev
