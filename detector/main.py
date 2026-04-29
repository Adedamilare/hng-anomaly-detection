#!/usr/bin/env python3
# detector/main.py - FIXED VERSION

import asyncio
import signal
import sys
import os
import yaml
import logging
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from monitor import LogMonitor
from baseline import BaselineEngine
from detector import Detector
from blocker import Blocker
from unbanner import Unbanner
from notifier import Notifier
from dashboard import Dashboard


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
    return logging.getLogger(__name__)


class AnomalyDetectionEngine:
    def __init__(self, config_path: str):
        self.logger = setup_logging()
        
        # Load config with error handling
        try:
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f)
            self.logger.info("Configuration loaded successfully")
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            sys.exit(1)

        # Validate required config keys
        required_keys = ['detection', 'blocking', 'audit', 'dashboard', 'monitoring']
        for key in required_keys:
            if key not in self.config:
                self.logger.error(f"Missing required config section: {key}")
                sys.exit(1)

        # Set default for min_data_points_for_baseline if missing
        if 'min_data_points_for_baseline' not in self.config['detection']:
            self.config['detection']['min_data_points_for_baseline'] = 10
            self.logger.info("Using default min_data_points_for_baseline: 10")

        self.running = True
        self.setup_audit_log()


    def setup_audit_log(self):
        audit_log_path = self.config['audit']['log_file']
        os.makedirs(os.path.dirname(audit_log_path), exist_ok=True)
        self.audit_logger = logging.getLogger('audit')
        handler = logging.FileHandler(audit_log_path)
        handler.setFormatter(logging.Formatter('[%(asctime)s] %(message)s'))
        self.audit_logger.addHandler(handler)
        self.audit_logger.setLevel(logging.INFO)


    def audit_log(self, action: str, details: str):
        self.audit_logger.info(f"{action} {details}")


    async def initialize(self):
        self.logger.info("Initializing components...")
        self.baseline_engine = BaselineEngine(self.config['detection'])
        self.blocker = Blocker()
        self.notifier = Notifier(self.config['slack']['webhook_url'])
        self.unbanner = Unbanner(
            self.config['blocking']['backoff_schedule'],
            self.config['blocking']['permanent_after_attempts'],
            self.blocker,
            self.notifier,
            self.audit_log
        )
        self.detector = Detector(
            self.config['detection'],
            self.baseline_engine,
            self.unbanner,
            self.notifier,
            self.audit_log
        )
        self.monitor = LogMonitor(
            self.config['monitoring']['log_file_path'],
            self.detector
        )
        self.dashboard = Dashboard(
            self.config['dashboard']['port'],
            self.config['dashboard']['host'],
            self.config['dashboard']['refresh_interval_seconds'],
            self.detector,
            self.baseline_engine,
            self.blocker
        )


    async def start(self):
        self.logger.info("Starting anomaly detection engine...")
        tasks = [
            asyncio.create_task(self.baseline_engine.start()),
            asyncio.create_task(self.unbanner.start()),
            asyncio.create_task(self.dashboard.start()),
            asyncio.create_task(self.monitor.start()),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)


    async def run(self):
        await self.initialize()
        await self.start()

if __name__ == "__main__":
    engine = AnomalyDetectionEngine('config.yaml')
    asyncio.run(engine.run())
