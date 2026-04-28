import aiohttp
import asyncio
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from collections import defaultdict
import re

logger = logging.getLogger(__name__)


class Notifier:
    def __init__(self, webhook_url: str, config: Optional[Dict] = None):
        self.webhook_url = webhook_url
        self.config = config or {}
        
        self._validate_webhook_url()

        self.rate_limit_enabled = self.config.get('rate_limit_enabled', True)
        self.min_alert_interval_seconds = self.config.get('min_alert_interval_seconds', 300)
        self.last_alert_time = defaultdict(float)

        self.max_retries = self.config.get('max_retries', 3)
        self.retry_delay_seconds = self.config.get('retry_delay_seconds', 1)

        self._session: Optional[aiohttp.ClientSession] = None
        self._session_lock = asyncio.Lock()

        self.timeout_seconds = self.config.get('timeout_seconds', 10)

        self.failed_alerts_count = 0
        self.successful_alerts_count = 0

        self.ip_alert_throttle = self.config.get('ip_alert_throttle_seconds', 3600)  


    def _validate_webhook_url(self):
        """Fix 8: Validate webhook URL format"""
        if self.webhook_url == "hng-anomaly-detection.slack.com":
            logger.warning("Using simulated mode - no real Slack notifications will be sent")
            return

        if not self.webhook_url.startswith(('https://', 'http://')):
            raise ValueError(f"Invalid webhook URL: {self.webhook_url}")

        if 'hooks.slack.com' not in self.webhook_url:
            logger.warning(f"Webhook URL doesn't look like a Slack webhook: {self.webhook_url}")


    async def _get_session(self) -> aiohttp.ClientSession:
        """Fix 4: Get or create reusable session"""
        if self._session is None or self._session.closed:
            async with self._session_lock:
                if self._session is None or self._session.closed:
                    timeout = aiohttp.ClientTimeout(total=self.timeout_seconds)
                    connector = aiohttp.TCPConnector(limit=10)  # Max 10 concurrent connections
                    self._session = aiohttp.ClientSession(timeout=timeout, connector=connector)
        return self._session


    async def close(self):
        """Close the session properly"""
        if self._session and not self._session.closed:
            await self._session.close()
            logger.debug("Notifier session closed")


    async def _check_rate_limit(self, key: str, interval_seconds: int) -> bool:
        """Fix 3: Check if we should rate limit this alert"""
        if not self.rate_limit_enabled:
            return True

        now = datetime.now().timestamp()
        last = self.last_alert_time.get(key, 0)

        if now - last < interval_seconds:
            logger.debug(f"Rate limiting alert for {key}")
            return False

        self.last_alert_time[key] = now
        return True


    async def _send_with_retry(self, message: str, retry_count: int = 0) -> bool:
        """Fix 2: Send with retry logic"""
        try:
            if len(message) > 3800:
                message = message[:3800] + "... (truncated)"

            session = await self._get_session()

            async with session.post(self.webhook_url, json={'text': message}) as response:
                if response.status == 200:
                    self.successful_alerts_count += 1
                    logger.debug(f"Alert sent successfully")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"Slack API error {response.status}: {error_text[:200]}")
                    raise Exception(f"HTTP {response.status}: {error_text[:100]}")

        except asyncio.TimeoutError:
            logger.error(f"Timeout sending alert (attempt {retry_count + 1}/{self.max_retries})")
        except aiohttp.ClientError as e:
            logger.error(f"Client error sending alert: {e} (attempt {retry_count + 1}/{self.max_retries})")
        except Exception as e:
            logger.error(f"Unexpected error sending alert: {e} (attempt {retry_count + 1}/{self.max_retries})")

        # Retry logic
        if retry_count < self.max_retries:
            await asyncio.sleep(self.retry_delay_seconds * (retry_count + 1))  # Exponential backoff
            return await self._send_with_retry(message, retry_count + 1)

        self.failed_alerts_count += 1
        logger.error(f"Failed to send alert after {self.max_retries} attempts")
        return False


    async def _send(self, message: str, alert_key: Optional[str] = None):
        """Send message with rate limiting"""
        # Fix 9: Check rate limiting if key provided
        if alert_key:
            if not await self._check_rate_limit(alert_key, self.ip_alert_throttle):
                logger.debug(f"Skipping alert due to throttling: {alert_key}")
                return

        if self.webhook_url == "hng-anomaly-detection.slack.com":
            logger.info(f"SIMULATED ALERT: {message}")
            return

        # Don't await - fire and forget to avoid blocking
        asyncio.create_task(self._send_with_retry(message))


    async def send_ban_alert(self, ip: str, rate: float, baseline: float, condition: str, duration: str):
        """Send alert when IP is banned"""
        message = (
            f"🚨 *ANOMALY DETECTED - IP BLOCKED*\n"
            f"• IP: `{ip}`\n"
            f"• Rate: `{rate:.2f} req/s`\n"
            f"• Baseline: `{baseline:.2f}`\n"
            f"• Condition: `{condition}`\n"
            f"• Duration: `{duration}`\n"
            f"• Time: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
        )

        await self._send(message, alert_key=f"ban_{ip}")


    async def send_global_alert(self, rate: float, baseline: float, condition: str):
        """Send alert for global anomalies"""
        message = (
            f"🌍 *GLOBAL ANOMALY*\n"
            f"• Rate: `{rate:.2f} req/s`\n"
            f"• Baseline: `{baseline:.2f}`\n"
            f"• Condition: `{condition}`\n"
            f"• Time: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
        )

        await self._send(message, alert_key="global_alert")


    async def send_unban_alert(self, ip: str, duration_blocked: str):
        """Send alert when IP is unbanned"""
        message = (
            f"✅ *IP UNBANNED*\n"
            f"• IP: `{ip}`\n"
            f"• Duration blocked: `{duration_blocked}`\n"
            f"• Time: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
        )

        await self._send(message, alert_key=f"unban_{ip}")


    async def send_test_alert(self) -> bool:
        """Send a test alert to verify configuration"""
        message = (
            f"🧪 *TEST ALERT*\n"
            f"• Status: `Anomaly detection engine running`\n"
            f"• Time: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`\n"
            f"• Stats: Success={self.successful_alerts_count}, Failed={self.failed_alerts_count}"
        )

        return await self._send_with_retry(message)

    async def get_stats(self) -> Dict[str, Any]:
        """Get notifier statistics"""
        return {
            'webhook_configured': self.webhook_url != "hng-anomaly-detection.slack.com",
            'successful_alerts': self.successful_alerts_count,
            'failed_alerts': self.failed_alerts_count,
            'rate_limit_enabled': self.rate_limit_enabled,
            'max_retries': self.max_retries,
            'timeout_seconds': self.timeout_seconds,
            'active_alert_throttles': len(self.last_alert_time)
        }


    async def __aenter__(self):
        return self


    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
