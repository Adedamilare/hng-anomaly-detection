import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, List
import re
from enum import Enum

logger = logging.getLogger(__name__)


class BanStatus(Enum):
    TEMPORARY = "temporary"
    PERMANENT = "permanent"
    PENDING_UNBAN = "pending_unban"


class Unbanner:
    def __init__(self, schedule: List[str], permanent_after: int, blocker, notifier, audit_logger):
        # Fix 6: Validate schedule
        if not schedule:
            raise ValueError("Schedule cannot be empty")

        self.schedule = schedule
        self.permanent_after = permanent_after
        self.blocker = blocker
        self.notifier = notifier
        self.audit_log_func = audit_logger  
        self.bans: Dict[str, Dict] = {}
        self.running = False
        self._lock = asyncio.Lock()  
        self._stop_event = asyncio.Event()
        self._process_task: Optional[asyncio.Task] = None

        self.process_interval_seconds = 10

        # Track stats
        self.stats = {
            'total_bans': 0,
            'permanent_bans': 0,
            'successful_unbans': 0,
            'failed_unbans': 0
        }


    async def start(self):
        """Start the unbanner processing loop"""
        if self.running:
            logger.warning("Unbanner already running")
            return

        self.running = True
        self._stop_event.clear()
        self._process_task = asyncio.create_task(self._process_loop())
        logger.info("Unbanner started")


    async def stop(self):
        """Fix 3: Graceful shutdown"""
        logger.info("Stopping unbanner...")
        self.running = False
        self._stop_event.set()

        if self._process_task:
            try:
                await asyncio.wait_for(self._process_task, timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning("Unbanner process loop did not stop gracefully")
                self._process_task.cancel()

        logger.info("Unbanner stopped")


    async def _process_loop(self):
        """Main processing loop"""
        while self.running:
            try:
                await self.process()
                await asyncio.sleep(self.process_interval_seconds)
            except Exception as e:
                logger.error(f"Error in unbanner process loop: {e}")
                await asyncio.sleep(1)  # Brief pause before retry


    async def schedule_unban(self, ip: str, duration: str) -> bool:
        """Schedule an unban for an IP address"""
        async with self._lock:
            current_time = datetime.now()

            if ip not in self.bans:
                self.bans[ip] = {
                    'attempts': 0,
                    'ban_history': [],
                    'status': BanStatus.TEMPORARY
                }
                self.stats['total_bans'] += 1

            ban_info = self.bans[ip]
            ban_info['attempts'] += 1
            ban_info['last_ban_time'] = current_time

            if ban_info['attempts'] >= self.permanent_after:
                logger.warning(f"Permanent ban for {ip} after {ban_info['attempts']} attempts")
                ban_info['status'] = BanStatus.PERMANENT
                self.stats['permanent_bans'] += 1

                if 'unban_at' in ban_info:
                    del ban_info['unban_at']

                # Log permanent ban
                self.audit_log_func(f"PERMANENT_BAN ip={ip} attempts={ban_info['attempts']}")
                return True

            # Calculate unban time
            idx = ban_info['attempts'] - 1
            if idx < len(self.schedule):
                delay = self._parse_duration(self.schedule[idx])
                unban_at = current_time + delay
                ban_info['unban_at'] = unban_at
                ban_info['status'] = BanStatus.PENDING_UNBAN

                ban_info['ban_history'].append({
                    'attempt': ban_info['attempts'],
                    'duration': self.schedule[idx],
                    'scheduled_at': current_time,
                    'unban_at': unban_at
                })

                logger.info(f"Scheduled unban for {ip} in {self.schedule[idx]} (attempt {ban_info['attempts']})")
                self.audit_log_func(f"SCHEDULE_UNBAN ip={ip} duration={self.schedule[idx]} attempt={ban_info['attempts']}")
                return True
            else:
                # Should not happen if schedule is valid
                logger.error(f"No schedule entry for attempt {ban_info['attempts']} for {ip}")
                return False


    async def process(self):
        """Process and execute pending unbans"""
        async with self._lock:
            now = datetime.now()
            ips_to_unban = []

            # Find IPs ready for unban
            for ip, data in self.bans.items():
                # Fix 4: Skip permanent bans
                if data.get('status') == BanStatus.PERMANENT:
                    continue

                if 'unban_at' in data and now >= data['unban_at']:
                    ips_to_unban.append(ip)

            # Process unbans outside the lock to avoid blocking
            for ip in ips_to_unban:
                await self._execute_unban(ip)


    async def _execute_unban(self, ip: str):
        """Fix 9: Execute unban with error handling"""
        try:
            # Attempt to unblock
            success = await self.blocker.unblock_ip(ip)

            if success:
                async with self._lock:
                    if ip in self.bans:
                        ban_info = self.bans[ip]
                        self.stats['successful_unbans'] += 1

                        # Log successful unban
                        duration_blocked = datetime.now() - ban_info.get('last_ban_time', datetime.now())
                        self.audit_log_func(f"UNBAN ip={ip} attempts={ban_info['attempts']} duration={duration_blocked}")

                        # Send notification
                        try:
                            await self.notifier.send_unban_alert(ip, str(duration_blocked))
                        except Exception as e:
                            logger.error(f"Failed to send unban notification for {ip}: {e}")

                        # Remove from active bans (keep history if needed)
                        del self.bans[ip]

                        logger.info(f"Successfully unbanned {ip}")
                return

            self.stats['failed_unbans'] += 1
            logger.error(f"Failed to unblock {ip} - may need manual intervention")

            async with self._lock:
                if ip in self.bans and 'unban_at' in self.bans[ip]:
                    # Retry after 1 minute
                    self.bans[ip]['unban_at'] = datetime.now() + timedelta(minutes=1)
                    logger.info(f"Rescheduled unban for {ip} in 1 minute (retry)")

        except Exception as e:
            logger.error(f"Exception during unban for {ip}: {e}")
            self.stats['failed_unbans'] += 1


    def _parse_duration(self, duration: str) -> timedelta:
        """Fix 1: Parse duration string with multiple units"""
        if not duration:
            logger.warning("Empty duration, using default 10 minutes")
            return timedelta(minutes=10)

        patterns = [
            (r'(\d+)\s*[sS]', 'seconds'),      # 30s, 30S
            (r'(\d+)\s*[mM]', 'minutes'),      # 10m, 10M
            (r'(\d+)\s*[hH]', 'hours'),        # 2h, 2H
            (r'(\d+)\s*[dD]', 'days'),         # 1d, 1D
            (r'(\d+)\s*[wW]', 'weeks'),        # 1w, 1W
        ]

        for pattern, unit in patterns:
            match = re.match(pattern, duration.strip())
            if match:
                val = int(match.group(1))
                if unit == 'seconds':
                    return timedelta(seconds=val)
                elif unit == 'minutes':
                    return timedelta(minutes=val)
                elif unit == 'hours':
                    return timedelta(hours=val)
                elif unit == 'days':
                    return timedelta(days=val)
                elif unit == 'weeks':
                    return timedelta(weeks=val)

        try:
            minutes = int(duration)
            logger.debug(f"Parsed '{duration}' as {minutes} minutes")
            return timedelta(minutes=minutes)
        except ValueError:
            logger.warning(f"Could not parse duration '{duration}', using default 10 minutes")
            return timedelta(minutes=10)


    async def get_ban_info(self, ip: str) -> Optional[Dict]:
        """Get ban information for an IP"""
        async with self._lock:
            if ip in self.bans:
                return self.bans[ip].copy()
        return None


    async def get_all_bans(self) -> Dict:
        """Get all current bans"""
        async with self._lock:
            return {
                ip: {
                    'attempts': data['attempts'],
                    'status': data.get('status', BanStatus.TEMPORARY).value,
                    'unban_at': data.get('unban_at').isoformat() if data.get('unban_at') else None,
                    'last_ban_time': data.get('last_ban_time').isoformat() if data.get('last_ban_time') else None
                }
                for ip, data in self.bans.items()
            }


    async def get_stats(self) -> Dict[str, Any]:
        """Get unbanner statistics"""
        async with self._lock:
            return {
                'total_bans': self.stats['total_bans'],
                'permanent_bans': self.stats['permanent_bans'],
                'successful_unbans': self.stats['successful_unbans'],
                'failed_unbans': self.stats['failed_unbans'],
                'active_bans': len(self.bans),
                'temporary_bans': sum(1 for d in self.bans.values() if d.get('status') != BanStatus.PERMANENT),
                'permanent_bans_active': sum(1 for d in self.bans.values() if d.get('status') == BanStatus.PERMANENT),
                'process_interval_seconds': self.process_interval_seconds,
                'schedule': self.schedule,
                'permanent_after': self.permanent_after
            }


    async def manual_unban(self, ip: str) -> bool:
        """Manually unban an IP (admin action)"""
        async with self._lock:
            if ip not in self.bans:
                logger.warning(f"IP {ip} is not currently banned")
                return False

            ban_info = self.bans[ip]
            logger.info(f"Manually unbanning {ip} (attempts: {ban_info['attempts']})")

            # Remove from bans dictionary
            del self.bans[ip]

        # Attempt to unblock
        success = await self.blocker.unblock_ip(ip)

        if success:
            self.audit_log_func(f"MANUAL_UNBAN ip={ip} attempts={ban_info['attempts']}")
            logger.info(f"Successfully manually unbanned {ip}")
        else:
            logger.error(f"Failed to manually unban {ip}")

        return success


    async def __aenter__(self):
        await self.start()
        return self


    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()
