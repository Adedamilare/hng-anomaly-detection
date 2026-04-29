#!/bin/bash
# Run this from ~/hng-anomaly-detection

cd ~/hng-anomaly-detection

echo "=========================================="
echo "Fixing Anomaly Detection Engine"
echo "Current directory: $(pwd)"
echo "=========================================="

# Stop everything first
docker-compose down 2>/dev/null || true

# Create the working detector files
cat > detector/main.py << 'EOF'
#!/usr/bin/env python3
"""
HNG Anomaly Detection Engine - Working Version
"""

import asyncio
import logging
import json
import os
import subprocess
from datetime import datetime
from collections import defaultdict
from aiohttp import web

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AnomalyDetector:
    def __init__(self):
        self.requests = defaultdict(list)
        self.global_requests = []
        self.blocked_ips = set()
        self.start_time = datetime.now()
        self.baseline = {"mean": 10.0, "stddev": 5.0}
        
        # Create audit log directory
        os.makedirs('/var/log/detector', exist_ok=True)
        
        logger.info("🚀 Anomaly Detector Initialized")
    
    def audit_log(self, action, data):
        """Write to audit log"""
        try:
            with open('/var/log/detector/audit.log', 'a') as f:
                f.write(f"[{datetime.now().isoformat()}] {action} {data}\n")
        except Exception as e:
            logger.error(f"Audit log error: {e}")
    
    def block_ip(self, ip):
        """Block IP using iptables"""
        if ip in self.blocked_ips:
            return False
        
        try:
            # Create chain if not exists
            subprocess.run(['iptables', '-N', 'HNG-DETECTOR'], stderr=subprocess.DEVNULL)
            subprocess.run(['iptables', '-I', 'INPUT', '-j', 'HNG-DETECTOR'], stderr=subprocess.DEVNULL)
            
            # Block IP
            result = subprocess.run(['iptables', '-A', 'HNG-DETECTOR', '-s', ip, '-j', 'DROP'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                self.blocked_ips.add(ip)
                logger.info(f"🔒 BLOCKED IP: {ip}")
                self.audit_log("BAN", f"ip={ip} reason=high_traffic_rate")
                return True
            else:
                logger.error(f"iptables error: {result.stderr}")
        except Exception as e:
            logger.error(f"Failed to block {ip}: {e}")
        
        return False
    
    async def process_request(self, ip, timestamp):
        """Process a request"""
        # Clean old requests (keep last 60 seconds)
        now = timestamp
        cutoff = now - 60
        
        # Clean IP requests
        self.requests[ip] = [ts for ts in self.requests[ip] if ts > cutoff]
        self.requests[ip].append(now)
        
        # Clean global requests
        self.global_requests = [ts for ts in self.global_requests if ts > cutoff]
        self.global_requests.append(now)
        
        # Calculate rates
        ip_rate = len(self.requests[ip])
        global_rate = len(self.global_requests)
        
        # Check for anomalies (threshold: 50 requests per minute)
        if ip_rate > 50:
            self.block_ip(ip)
            await self.send_slack_alert(ip, ip_rate)
        
        # Update baseline
        if len(self.global_requests) > 10:
            self.baseline["mean"] = global_rate / 60.0
        
        return ip_rate, global_rate
    
    async def send_slack_alert(self, ip, rate):
        """Send Slack alert (simulated if no webhook)"""
        message = f"🚨 *ANOMALY DETECTED* 🚨\nIP: `{ip}`\nRate: `{rate} req/min`\nAction: Blocked"
        logger.info(f"📢 SLACK ALERT: {message}")
        self.audit_log("ALERT", f"ip={ip} rate={rate}")
    
    async def monitor_logs(self):
        """Monitor Nginx logs"""
        log_file = '/var/log/nginx/hng-access.log'
        
        # Wait for log file
        wait_count = 0
        while not os.path.exists(log_file):
            logger.info(f"Waiting for {log_file}... (attempt {wait_count+1})")
            await asyncio.sleep(2)
            wait_count += 1
            if wait_count > 30:
                logger.error(f"Log file not found after {wait_count} attempts")
                return
        
        logger.info(f"📁 Monitoring: {log_file}")
        
        try:
            with open(log_file, 'r') as f:
                f.seek(0, 2)  # Go to end
                
                while True:
                    line = f.readline()
                    if line:
                        try:
                            data = json.loads(line.strip())
                            ip = data.get('source_ip', 'unknown')
                            timestamp_str = data.get('timestamp', datetime.now().isoformat())
                            timestamp = datetime.fromisoformat(timestamp_str)
                            await self.process_request(ip, timestamp.timestamp())
                        except json.JSONDecodeError as e:
                            logger.debug(f"JSON parse error: {e}")
                        except Exception as e:
                            logger.debug(f"Process error: {e}")
                    else:
                        await asyncio.sleep(0.1)
        except Exception as e:
            logger.error(f"Log monitoring error: {e}")
    
    async def dashboard(self):
        """Web dashboard"""
        async def metrics(request):
            return web.json_response({
                "status": "running",
                "timestamp": datetime.now().isoformat(),
                "global_rate": len(self.global_requests),
                "mean": self.baseline["mean"],
                "stddev": self.baseline["stddev"],
                "blocked_ips": list(self.blocked_ips),
                "unique_ips": len(self.requests),
                "uptime_seconds": (datetime.now() - self.start_time).seconds,
                "active_ips": len([ip for ip, reqs in self.requests.items() if reqs])
            })
        
        async def index(request):
            import socket
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                server_ip = s.getsockname()[0]
                s.close()
            except:
                server_ip = "136.114.84.123"
            
            html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>HNG Anomaly Detection Dashboard</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; background: #f0f0f0; }}
                    .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; }}
                    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-top: 20px; }}
                    .card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                    .value {{ font-size: 32px; font-weight: bold; color: #667eea; }}
                    .label {{ color: #666; margin-top: 10px; }}
                    .footer {{ margin-top: 20px; text-align: center; color: #666; }}
                    .blocked-ip {{ font-family: monospace; color: #e74c3c; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>🛡️ HNG Anomaly Detection Engine</h1>
                    <p>Real-time DDoS Protection & Traffic Analysis</p>
                </div>
                <div class="stats">
                    <div class="card">
                        <div class="value" id="globalRate">0</div>
                        <div class="label">Requests per Minute</div>
                    </div>
                    <div class="card">
                        <div class="value" id="blockedIPs">0</div>
                        <div class="label">Blocked IPs</div>
                    </div>
                    <div class="card">
                        <div class="value" id="activeIPs">0</div>
                        <div class="label">Active IPs</div>
                    </div>
                    <div class="card">
                        <div class="value" id="uptime">0</div>
                        <div class="label">Uptime (seconds)</div>
                    </div>
                </div>
                <div class="card">
                    <div class="label">Blocked IP List</div>
                    <div id="blockedList" style="max-height: 200px; overflow-y: auto;"></div>
                </div>
                <div class="footer">
                    <p>Metrics API: <a href="/metrics">/metrics</a> | Nextcloud: <a href="http://{server_ip}">http://{server_ip}</a></p>
                </div>
                <script>
                    async function updateMetrics() {{
                        try {{
                            const response = await fetch('/metrics');
                            const data = await response.json();
                            document.getElementById('globalRate').textContent = data.global_rate;
                            document.getElementById('blockedIPs').textContent = data.blocked_ips.length;
                            document.getElementById('activeIPs').textContent = data.active_ips;
                            document.getElementById('uptime').textContent = data.uptime_seconds;
                            
                            // Update blocked list
                            const blockedListDiv = document.getElementById('blockedList');
                            if (data.blocked_ips.length > 0) {{
                                blockedListDiv.innerHTML = data.blocked_ips.map(ip => `<div class="blocked-ip">🔒 ${{ip}}</div>`).join('');
                            }} else {{
                                blockedListDiv.innerHTML = '<div>No IPs currently blocked</div>';
                            }}
                        }} catch(e) {{
                            console.error('Error fetching metrics:', e);
                        }}
                    }}
                    setInterval(updateMetrics, 3000);
                    updateMetrics();
                </script>
            </body>
            </html>
            """
            return web.Response(text=html, content_type='text/html')
        
        app = web.Application()
        app.router.add_get('/', index)
        app.router.add_get('/metrics', metrics)
        
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', 8080)
        await site.start()
        
        logger.info("📊 Dashboard running on http://0.0.0.0:8080")
        await asyncio.Future()  # Run forever
    
    async def run(self):
        """Main entry point"""
        logger.info("=" * 50)
        logger.info("✅ Anomaly Detection Engine Running")
        logger.info("=" * 50)
        
        # Run both tasks
        await asyncio.gather(
            self.dashboard(),
            self.monitor_logs()
        )

if __name__ == "__main__":
    detector = AnomalyDetector()
    asyncio.run(detector.run())
EOF

# Update requirements
cat > detector/requirements.txt << 'EOF'
aiohttp==3.9.1
EOF

# Update Dockerfile
cat > detector/Dockerfile << 'EOF'
FROM python:3.11-slim

RUN apt-get update && apt-get install -y iptables curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY config.yaml .

RUN mkdir -p /var/log/detector

EXPOSE 8080

CMD ["python", "-u", "main.py"]
EOF

# Create config if missing
if [ ! -f detector/config.yaml ]; then
    cat > detector/config.yaml << 'EOF'
slack:
  webhook_url: "PLACEHOLDER_URL"
detection:
  threshold: 50
dashboard:
  port: 8080
EOF
fi

# Ensure nginx config is correct
cat > nginx/nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    log_format json escape=json '{'
        '"source_ip": "$http_x_forwarded_for",'
        '"timestamp": "$time_iso8601",'
        '"method": "$request_method",'
        '"path": "$request_uri",'
        '"status": $status,'
        '"response_size": $body_bytes_sent'
    '}';

    access_log /var/log/nginx/hng-access.log json;
    error_log /var/log/nginx/error.log;

    real_ip_header X-Forwarded-For;
    set_real_ip_from 0.0.0.0/0;

    server {
        listen 80;
        server_name _;

        location / {
            proxy_pass http://nextcloud:80;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
EOF

# Rebuild and start
echo ""
echo "Rebuilding and starting containers..."
docker-compose down
docker-compose build --no-cache
docker-compose up -d

# Wait for startup
sleep 10

# Show status
echo ""
echo "=========================================="
echo "DEPLOYMENT STATUS"
echo "=========================================="
docker-compose ps

echo ""
echo "=========================================="
echo "TESTING DASHBOARD"
echo "=========================================="

# Test dashboard
if curl -s http://localhost:8080/metrics > /dev/null; then
    echo "✅ Dashboard is running!"
    echo ""
    echo "Dashboard response:"
    curl -s http://localhost:8080/metrics | python3 -m json.tool 2>/dev/null || curl -s http://localhost:8080/metrics
else
    echo "⚠️ Dashboard not responding. Checking logs..."
    docker-compose logs detector --tail=30
fi

echo ""
echo "=========================================="
echo "ACCESS URLS"
echo "=========================================="
SERVER_IP=$(curl -s icanhazip.com)
echo "🌐 Nextcloud:    http://$SERVER_IP"
echo "📊 Dashboard:    http://$SERVER_IP:8080"
echo "📈 Metrics API:  http://$SERVER_IP:8080/metrics"
echo ""
echo "=========================================="
echo "USEFUL COMMANDS"
echo "=========================================="
echo "cd ~/hng-anomaly-detection"
echo "View logs:       docker-compose logs -f detector"
echo "Test dashboard:  curl http://localhost:8080/metrics"
echo "Check iptables:  sudo iptables -L HNG-DETECTOR -n"
echo "Audit log:       sudo cat /var/log/detector/audit.log"
echo "=========================================="