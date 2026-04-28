from aiohttp import web
import jinja2
import psutil
import asyncio
import logging
import time
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

class Dashboard:
    def __init__(self, port, host, refresh_interval, detector, baseline_engine, blocker):
        self.port = port
        self.host = host
        self.refresh_interval = refresh_interval
        self.detector = detector
        self.baseline_engine = baseline_engine
        self.blocker = blocker
        self.start_time = time.time()
        self.runner = None
        self.site = None
        self._shutdown_event = asyncio.Event()

        template_dir = Path(__file__).parent / 'templates'
        template_dir.mkdir(exist_ok=True)

        # Create default template if it doesn't exist
        default_template = template_dir / 'index.html'
        if not default_template.exists():
            default_template.write_text("""
<!DOCTYPE html>
<html>
<head>
    <title>Anomaly Detection Dashboard</title>
    <meta http-equiv="refresh" content="{{ refresh_interval }}">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .metric { margin: 10px 0; padding: 10px; border: 1px solid #ccc; }
        .good { color: green; }
        .warning { color: orange; }
        .critical { color: red; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Anomaly Detection Dashboard</h1>

    <div class="metric">
        <h2>System Metrics</h2>
        <p>Uptime: {{ uptime }}</p>
        <p>CPU Usage: {{ cpu_percent }}%</p>
        <p>Memory Usage: {{ memory_percent }}%</p>
    </div>

    <div class="metric">
        <h2>Detection Metrics</h2>
        <p>Current Rate: {{ current_rate }} req/sec</p>
        <p>Baseline Mean: {{ mean }} req/sec</p>
        <p>Baseline StdDev: {{ stddev }}</p>
        <p>Z-Score: {{ z_score }}</p>
    </div>

    <div class="metric">
        <h2>Blocked IPs ({{ blocked_count }})</h2>
        {% if blocked_ips %}
        <table>
            <tr><th>IP Address</th><th>Blocked Since</th></tr>
            {% for ip, time in blocked_ips %}
            <tr><td>{{ ip }}</td><td>{{ time }}</td></tr>
            {% endfor %}
        </table>
        {% else %}
        <p>No IPs currently blocked</p>
        {% endif %}
    </div>
</body>
</html>
""")


        self.template_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(template_dir),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )

        self.app = web.Application()
        self.setup_routes()


    def setup_routes(self):
        self.app.router.add_get('/', self.index)
        self.app.router.add_get('/metrics', self.metrics)
        self.app.router.add_get('/health', self.health)
        self.app.router.add_post('/unblock/{ip}', self.unblock_ip)


    async def get_system_metrics(self):
        """Fix 2: Add real system metrics with non-blocking calls"""
        # Run CPU/memory checks in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        cpu_percent = await loop.run_in_executor(None, psutil.cpu_percent, 1)
        memory_percent = await loop.run_in_executor(None, lambda: psutil.virtual_memory().percent)

        return {
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent
        }


    async def get_blocked_ips_with_time(self):
        """Fix 6: Handle blocker.blocked_ips safely"""
        try:
            if hasattr(self.blocker, 'get_blocked_ips_with_time'):
                return await self.blocker.get_blocked_ips_with_time()
            elif hasattr(self.blocker, 'blocked_ips'):
                blocked = self.blocker.blocked_ips
                if isinstance(blocked, set):
                    return [(ip, "Unknown") for ip in list(blocked)[:100]]  # Limit to 100
                elif isinstance(blocked, dict):
                    return [(ip, str(time)) for ip, time in list(blocked.items())[:100]]
            return []
        except Exception as e:
            logger.error(f"Error getting blocked IPs: {e}")
            return []


    async def index(self, request):
        """Fix 1: Render actual HTML template with real data"""
        try:

            try:
                mean, stddev = await self.baseline_engine.get_baseline()
            except Exception as e:
                logger.error(f"Failed to get baseline: {e}")
                mean, stddev = 0, 0

            # Get current rate from detector
            current_rate = 0
            z_score = 0
            if hasattr(self.detector, 'get_current_rate'):
                current_rate = await self.detector.get_current_rate()
                if stddev > 0:
                    z_score = (current_rate - mean) / stddev

            # Get system metrics
            system_metrics = await self.get_system_metrics()

            # Get blocked IPs
            blocked_ips = await self.get_blocked_ips_with_time()

            # Calculate uptime
            uptime_seconds = int(time.time() - self.start_time)
            uptime = f"{uptime_seconds // 3600}h {(uptime_seconds % 3600) // 60}m {uptime_seconds % 60}s"

            # Render template
            template = self.template_env.get_template('index.html')
            html = template.render(
                refresh_interval=self.refresh_interval,
                uptime=uptime,
                cpu_percent=system_metrics['cpu_percent'],
                memory_percent=system_metrics['memory_percent'],
                current_rate=round(current_rate, 2),
                mean=round(mean, 2),
                stddev=round(stddev, 2),
                z_score=round(z_score, 2),
                blocked_count=len(blocked_ips),
                blocked_ips=blocked_ips
            )
            return web.Response(text=html, content_type='text/html')

        except Exception as e:
            logger.error(f"Error rendering index: {e}")
            return web.Response(text=f"Dashboard error: {e}", status=500)


    async def metrics(self, request):
        """Return JSON metrics for API consumption"""
        try:
            mean, stddev = await self.baseline_engine.get_baseline()
            current_rate = 0
            if hasattr(self.detector, 'get_current_rate'):
                current_rate = await self.detector.get_current_rate()

            system_metrics = await self.get_system_metrics()
            uptime_seconds = int(time.time() - self.start_time)

            return web.json_response({
                'global_rate': round(current_rate, 2),
                'mean': round(mean, 2),
                'stddev': round(stddev, 2),
                'z_score': round((current_rate - mean) / stddev if stddev > 0 else 0, 2),
                'blocked_ips_count': len(await self.get_blocked_ips_with_time()),
                'uptime_seconds': uptime_seconds,
                'cpu_percent': system_metrics['cpu_percent'],
                'memory_percent': system_metrics['memory_percent']
            })
        except Exception as e:
            logger.error(f"Error getting metrics: {e}")
            return web.json_response({'error': str(e)}, status=500)


    async def health(self, request):
        """Health check endpoint"""
        return web.json_response({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat()
        })


    async def unblock_ip(self, request):
        """Manually unblock an IP"""
        ip = request.match_info.get('ip')
        if ip:
            if hasattr(self.blocker, 'unblock'):
                await self.blocker.unblock(ip)
                logger.info(f"Manually unblocked {ip}")
                return web.json_response({'status': 'unblocked', 'ip': ip})
        return web.json_response({'error': 'Invalid IP'}, status=400)


    async def start(self):
        """Fix 4: Proper startup with error handling"""
        try:
            self.runner = web.AppRunner(self.app)
            await self.runner.setup()
            self.site = web.TCPSite(self.runner, self.host, self.port)
            await self.site.start()
            logger.info(f"Dashboard running on http://{self.host}:{self.port}")
            logger.info(f"Health check: http://{self.host}:{self.port}/health")
            logger.info(f"Metrics API: http://{self.host}:{self.port}/metrics")


            await self._shutdown_event.wait()


        except Exception as e:
            logger.error(f"Failed to start dashboard: {e}")
            raise


    async def stop(self):
        """Fix 4: Add graceful shutdown method"""
        logger.info("Stopping dashboard...")
        self._shutdown_event.set()

        if self.runner:
            await self.runner.cleanup()
            logger.info("Dashboard stopped")


    async def __aenter__(self):
        await self.start()
        return self


    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()
