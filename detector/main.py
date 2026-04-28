#!/usr/bin/env python3
"""
Anomaly Detection Engine & DDoS Detection Tool
Main entry point
"""

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

        if not os.path.exists(config_path):
            self.logger.error(f"Configuration file {config_path} not found!")
            sys.exit(1)

        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)

        self.running = True
        self.setup_audit_log()
        self.setup_signal_handlers()  # Error 3: Add signal handlers


    def setup_signal_handlers(self):
        """Setup graceful shutdown signal handlers"""
        loop = asyncio.get_event_loop()
        for sig in [signal.SIGTERM, signal.SIGINT, signal.SIGQUIT]:
            loop.add_signal_handler(sig, lambda: asyncio.create_task(self.shutdown()))


    def setup_audit_log(self):
        audit_log_path = self.config.get('audit', {}).get('log_file', '/var/log/anomaly_audit.log')

        # Create directory if it doesn't exist
        log_dir = os.path.dirname(audit_log_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        self.audit_logger = logging.getLogger('audit')

        if self.audit_logger.handlers:
            self.audit_logger.handlers.clear()

        handler = logging.FileHandler(audit_log_path)
        handler.setFormatter(logging.Formatter('[%(asctime)s] %(message)s'))
        self.audit_logger.addHandler(handler)
        self.audit_logger.setLevel(logging.INFO)
        self.audit_logger.propagate = False  # Prevent propagation to root logger


    def audit_log(self, action: str, details: str):
        self.audit_logger.info(f"{action} {details}")


    async def shutdown(self):
        """Graceful shutdown"""
        self.logger.info("Shutting down gracefully...")
        self.running = False

        # Stop all components in reverse order
        if hasattr(self, 'monitor'):
            await self.monitor.stop()
        if hasattr(self, 'dashboard'):
            await self.dashboard.stop()
        if hasattr(self, 'unbanner'):
            await self.unbanner.stop()
        if hasattr(self, 'baseline_engine'):
            await self.baseline_engine.stop()

        self.logger.info("Shutdown complete")
        sys.exit(0)


    async def initialize(self):
        self.logger.info("Initializing components...")

        detection_config = self.config.get('detection', {})
        blocking_config = self.config.get('blocking', {})
        monitoring_config = self.config.get('monitoring', {})
        dashboard_config = self.config.get('dashboard', {})
        slack_config = self.config.get('slack', {})

        # Create components in order
        self.baseline_engine = BaselineEngine(detection_config)
        self.blocker = Blocker()

        # Initialize blocker first
        if not await self.blocker.initialize():
            raise RuntimeError("Failed to initialize blocker")

        self.notifier = Notifier(slack_config.get('webhook_url', ''))

        # Pass blocker to unbanner
        self.unbanner = Unbanner(
            blocking_config.get('backoff_schedule', []),
            blocking_config.get('permanent_after_attempts', 3),
            self.blocker,
            self.notifier,
            self.audit_log
        )

        # Pass blocker to detector
        self.detector = Detector(
            detection_config,
            self.baseline_engine,
            self.unbanner,
            self.notifier,
            self.audit_log,
            self.blocker 
        )

        # Start the detector
        await self.detector.start()

        # Create monitor with log format from config
        log_format = monitoring_config.get('log_format', 'json')

        self.monitor = LogMonitor(
            monitoring_config.get('log_file_path', '/var/log/syslog'),
            self.detector,
            log_format=log_format  # <-- Pass the format
        )

        self.dashboard = Dashboard(
            dashboard_config.get('port', 8080),
            dashboard_config.get('host', 'localhost'),
            dashboard_config.get('refresh_interval_seconds', 5),
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

        try:
            await asyncio.gather(*tasks, return_exceptions=False)
        except Exception as e:
            self.logger.error(f"Error in main tasks: {e}")
            await self.shutdown()


    async def run(self):
        await self.initialize()
        await self.start()

if __name__ == "__main__":
    # Error 6: Allow config path as command line argument
    config_file = sys.argv[1] if len(sys.argv) > 1 else 'config.yaml'
    engine = AnomalyDetectionEngine(config_file)

    try:
        asyncio.run(engine.run())
    except KeyboardInterrupt:
        print("\nReceived interrupt signal")
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)
