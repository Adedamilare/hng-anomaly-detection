import json
import asyncio
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import os

logger = logging.getLogger(__name__)


class LogEntry:
    def __init__(self, source_ip, timestamp, method, path, status, response_size):
        self.source_ip = source_ip
        self.timestamp = timestamp if isinstance(timestamp, datetime) else datetime.fromisoformat(timestamp)
        self.method = method
        self.path = path
        self.status = int(status) if isinstance(status, str) else status
        self.response_size = int(response_size) if isinstance(response_size, str) else response_size


class LogMonitor:
    NGINX_COMBINED_REGEX = re.compile(
        r'^(?P<source_ip>\S+) - \S+ \[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) \S+" '
        r'(?P<status>\d{3}) (?P<response_size>\d+)'
    )

    NGINX_JSON_FORMAT = 'json'
    NGINX_COMBINED_FORMAT = 'combined'


    def __init__(self, log_path: str, detector, log_format: str = 'json'):
        self.log_path = Path(log_path)
        self.detector = detector
        self.log_format = log_format
        self.running = False
        self._stop_event = asyncio.Event()
        self._file_handle = None
        self._position_file = Path(f"{log_path}.pos")
        self._last_position = 0


    async def start(self):
        """Start monitoring the log file"""
        logger.info(f"Monitoring {self.log_path} (format: {self.log_format})")

        # Wait for log file to exist
        while not self.log_path.exists() and self.running:
            logger.debug(f"Waiting for {self.log_path} to exist...")
            await asyncio.sleep(2)

        if not self.running:
            return

        await self._load_position()

        self.running = True

        while self.running:
            try:
                await self._monitor_file()
            except FileNotFoundError:
                logger.warning(f"Log file {self.log_path} disappeared, waiting for recreation...")
                await asyncio.sleep(5)
                self._file_handle = None
                continue
            except Exception as e:
                logger.error(f"Error monitoring file: {e}")
                await asyncio.sleep(1)


    async def _monitor_file(self):
        """Monitor a single file instance"""
        # Fix 2: Reopen file if needed
        if self._file_handle is None or self._file_handle.closed:
            self._file_handle = open(self.log_path, 'r', encoding='utf-8', errors='ignore')

            if self._last_position > 0:
                self._file_handle.seek(self._last_position)
            else:
                self._file_handle.seek(0, os.SEEK_END)
                self._last_position = self._file_handle.tell()
                await self._save_position()

        # Read lines
        while self.running:
            line = self._file_handle.readline()
            if not line:
                if self._is_file_rotated():
                    logger.info("Log file rotated, reopening...")
                    self._file_handle.close()
                    self._file_handle = None
                    self._last_position = 0
                    await self._save_position()
                    break

                # Wait for more data
                await asyncio.sleep(0.1)
                continue

            line = line.strip()
            if not line:
                continue

            # Update position
            self._last_position = self._file_handle.tell()
            await self._save_position()

            # Process the line
            await self.process_line(line)


    def _is_file_rotated(self) -> bool:
        """Fix 7: Check if log file has been rotated"""
        try:
            current_inode = os.stat(self.log_path).st_ino
            original_inode = self._file_handle.fileno() if self._file_handle else None
            return original_inode is not None and current_inode != os.fstat(original_inode).st_ino
        except Exception:
            return False


    async def _load_position(self):
        """Fix 5: Load last read position from file"""
        try:
            if self._position_file.exists():
                with open(self._position_file, 'r') as f:
                    self._last_position = int(f.read().strip())
                logger.debug(f"Loaded position {self._last_position} from {self._position_file}")
        except Exception as e:
            logger.warning(f"Could not load position: {e}")
            self._last_position = 0


    async def _save_position(self):
        """Fix 5: Save current read position"""
        try:
            with open(self._position_file, 'w') as f:
                f.write(str(self._last_position))
        except Exception as e:
            logger.warning(f"Could not save position: {e}")


    async def stop(self):
        """Fix 3: Graceful shutdown"""
        logger.info("Stopping log monitor...")
        self.running = False
        self._stop_event.set()

        # Save final position
        if self._file_handle and not self._file_handle.closed:
            self._last_position = self._file_handle.tell()
            await self._save_position()
            self._file_handle.close()

        logger.info("Log monitor stopped")


    async def process_line(self, line: str):
        """Process a single log line with support for multiple formats"""
        try:
            if self.log_format == 'json':
                entry = await self._parse_json_line(line)
            elif self.log_format == 'combined':
                entry = await self._parse_combined_line(line)
            elif self.log_format == 'auto':
                # Try to detect format
                entry = await self._parse_json_line(line)
                if entry is None:
                    entry = await self._parse_combined_line(line)
            else:
                logger.error(f"Unknown log format: {self.log_format}")
                return

            if entry:
                await self.detector.process_request(entry)

        except Exception as e:
            logger.error(f"Error processing line: {e}, line: {line[:200]}")


    async def _parse_json_line(self, line: str) -> Optional[LogEntry]:
        """Fix 1: Parse JSON log line"""
        try:
            data = json.loads(line)

            # Handle different JSON field names
            entry = LogEntry(
                source_ip=data.get('source_ip') or data.get('remote_addr') or data.get('ip', 'unknown'),
                timestamp=data.get('timestamp') or data.get('time_local') or datetime.now().isoformat(),
                method=data.get('method') or data.get('request_method', 'GET'),
                path=data.get('path') or data.get('request_uri') or data.get('request', '/').split()[1] if ' ' in data.get('request', '') else '/',
                status=data.get('status', 200),
                response_size=data.get('response_size') or data.get('body_bytes_sent', 0)
            )
            return entry
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.debug(f"JSON parsing failed: {e}")
            return None


    async def _parse_combined_line(self, line: str) -> Optional[LogEntry]:
        """Fix 1: Parse nginx combined log format"""
        match = self.NGINX_COMBINED_REGEX.match(line)
        if not match:
            logger.debug(f"Failed to parse combined log line: {line[:100]}")
            return None

        try:
            data = match.groupdict()

            # Parse timestamp (nginx format: "01/Jan/2024:12:34:56 +0000")
            timestamp_str = data['timestamp']
            try:
                # Try common nginx timestamp format
                timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                # Fallback to ISO format
                timestamp = datetime.now()

            entry = LogEntry(
                source_ip=data['source_ip'],
                timestamp=timestamp,
                method=data['method'],
                path=data['path'],
                status=int(data['status']),
                response_size=int(data['response_size'])
            )
            return entry
        except (ValueError, KeyError) as e:
            logger.debug(f"Combined log parsing failed: {e}")
            return None


    async def get_stats(self) -> Dict[str, Any]:
        """Get monitor statistics"""
        return {
            'log_path': str(self.log_path),
            'running': self.running,
            'log_format': self.log_format,
            'last_position': self._last_position,
            'file_exists': self.log_path.exists(),
            'file_size': self.log_path.stat().st_size if self.log_path.exists() else 0
        }
