import asyncio
import logging
import subprocess
from typing import Set
import os

logger = logging.getLogger(__name__)


class Blocker:
    CHAIN = "HNG-DETECTOR"


    def __init__(self):
        self.blocked_ips: Set[str] = set()
        self._lock = asyncio.Lock()
        self._initialized = False


    async def _run_iptables_command(self, *args: str, check: bool = True) -> tuple[bool, str]:
        """Run iptables command without blocking the event loop"""
        try:

            cmd = ["iptables"] + list(args)
            logger.debug(f"Running: {' '.join(cmd)}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if check and process.returncode != 0:
                error_msg = stderr.decode().strip()
                logger.error(f"Command failed: {' '.join(cmd)} - {error_msg}")
                return False, error_msg

            return process.returncode == 0, stderr.decode().strip()

        except FileNotFoundError:
            error_msg = "iptables command not found. Is iptables installed?"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Exception running iptables: {error_msg}")
            return False, error_msg


    async def _ensure_chain_exists(self) -> bool:
        """Fix 2: Ensure the custom chain exists in iptables"""
        # Check if chain exists
        success, _ = await self._run_iptables_command("-L", self.CHAIN, "-n", check=False)

        if not success:
            # Create the chain
            logger.info(f"Creating iptables chain: {self.CHAIN}")
            success, error = await self._run_iptables_command("-N", self.CHAIN)

            if not success:
                logger.error(f"Failed to create chain {self.CHAIN}: {error}")
                return False

            success, error = await self._run_iptables_command("-I", "INPUT", "-j", self.CHAIN)

            if not success:
                logger.error(f"Failed to add jump rule to INPUT: {error}")
                return False

            logger.info(f"Successfully initialized {self.CHAIN} chain")

        return True


    async def initialize(self) -> bool:
        """Fix 2: Initialize the blocker (check root, create chain)"""
        # Fix 3: Check for root privileges
        if os.geteuid() != 0:
            logger.error("Root privileges required for iptables operations")
            return False

        # Ensure chain exists
        if not await self._ensure_chain_exists():
            return False

        # Load existing blocked IPs from iptables (optional)
        await self._load_existing_blocked_ips()

        self._initialized = True
        logger.info("Blocker initialized successfully")
        return True


    async def _load_existing_blocked_ips(self):
        """Load already blocked IPs from iptables chain"""
        try:
            success, output = await self._run_iptables_command("-L", self.CHAIN, "-n", check=False)
            if success and output:
                # Parse iptables output to find blocked IPs
                for line in output.split('\n'):
                    if self.CHAIN in line and "-s" in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == "-s" and i + 1 < len(parts):
                                ip = parts[i + 1]
                                async with self._lock:
                                    self.blocked_ips.add(ip)
                                logger.debug(f"Loaded existing block for {ip}")
        except Exception as e:
            logger.warning(f"Could not load existing blocked IPs: {e}")

    async def block_ip(self, ip: str) -> bool:
        """Block an IP address"""
        # Fix 4: Check if already blocked
        async with self._lock:
            if ip in self.blocked_ips:
                logger.debug(f"IP {ip} already blocked, skipping")
                return True

        # Check if initialized
        if not self._initialized:
            if not await self.initialize():
                logger.error("Blocker not initialized, cannot block IP")
                return False

        try:
            # Check if rule already exists
            success, _ = await self._run_iptables_command(
                "-C", self.CHAIN, "-s", ip, "-j", "DROP", check=False
            )

            if not success:
                # Add the rule
                success, error = await self._run_iptables_command(
                    "-A", self.CHAIN, "-s", ip, "-j", "DROP"
                )

                if not success:
                    logger.error(f"Failed to block {ip}: {error}")
                    return False

            # Add to blocked set
            async with self._lock:
                self.blocked_ips.add(ip)

            logger.info(f"Blocked IP: {ip}")
            return True

        except Exception as e:
            logger.error(f"Exception while blocking {ip}: {e}")
            return False


    async def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address"""
        # Fix 5: Add proper error logging
        async with self._lock:
            if ip not in self.blocked_ips:
                logger.debug(f"IP {ip} is not blocked, nothing to unblock")
                return True

        try:
            # Delete the rule
            success, error = await self._run_iptables_command(
                "-D", self.CHAIN, "-s", ip, "-j", "DROP", check=False
            )

            if not success:
                # Rule might not exist - that's fine
                logger.debug(f"iptables rule for {ip} not found: {error}")

            # Remove from blocked set
            async with self._lock:
                self.blocked_ips.discard(ip)

            logger.info(f"Unblocked IP: {ip}")
            return True

        except Exception as e:
            logger.error(f"Failed to unblock {ip}: {e}")
            return False


    async def unblock_all(self) -> int:
        """Unblock all IPs"""
        async with self._lock:
            blocked_ips = list(self.blocked_ips)

        success_count = 0
        for ip in blocked_ips:
            if await self.unblock_ip(ip):
                success_count += 1
            await asyncio.sleep(0.1)  # Small delay to avoid overwhelming iptables

        logger.info(f"Unblocked {success_count}/{len(blocked_ips)} IPs")
        return success_count


    async def get_blocked_ips(self) -> Set[str]:
        """Get currently blocked IPs"""
        async with self._lock:
            return self.blocked_ips.copy()


    async def is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        async with self._lock:
            return ip in self.blocked_ips


    async def get_block_count(self) -> int:
        """Get number of blocked IPs"""
        async with self._lock:
            return len(self.blocked_ips)


    async def cleanup(self):
        """Fix 6: Cleanup - remove chain (optional, with caution)"""
        logger.warning("Cleaning up iptables rules...")

        # Unblock all IPs first
        await self.unblock_all()

        # Remove the jump rule from INPUT
        success, _ = await self._run_iptables_command("-D", "INPUT", "-j", self.CHAIN, check=False)

        # Flush and delete the chain
        if success:
            await self._run_iptables_command("-F", self.CHAIN, check=False)
            await self._run_iptables_command("-X", self.CHAIN, check=False)
            logger.info("Removed iptables chain")


    async def __aenter__(self):
        """Context manager entry"""
        await self.initialize()
        return self


    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup if needed"""
        # Don't auto-cleanup by default - only if explicitly requested
        pass
