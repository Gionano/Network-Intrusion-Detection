/* ══════════════════════════════════════════════════════════════════════
   IDS Dashboard — Frontend Application
   ══════════════════════════════════════════════════════════════════════ */

(function () {
    "use strict";

    // ─── Config ───
    const POLL_INTERVAL = 2000;      // stats polling (ms)
    const CHART_MAX_POINTS = 60;
    const MAX_FEED_ITEMS = 200;

    // ─── DOM refs ───
    const $totalPackets = document.getElementById("total-packets");
    const $totalAlerts  = document.getElementById("total-alerts");
    const $blockedCount = document.getElementById("blocked-count");
    const $pps          = document.getElementById("pps");
    const $uptime       = document.getElementById("uptime");
    const $statusBadge  = document.getElementById("status-badge");
    const $statusText   = document.getElementById("status-text");
    const $alertFeed    = document.getElementById("alert-feed");
    const $feedCount    = document.getElementById("feed-count");
    const $blockedList  = document.getElementById("blocked-list");

    // ─── Charts ───
    let packetChart, classChart;
    const ppsHistory = [];
    const classData = { "Port Scan": 0, "DDoS": 0, "Brute Force": 0, "Exfiltration": 0 };

    const chartColors = {
        "Port Scan":     "#ffab40",
        "DDoS":          "#ff5252",
        "Brute Force":   "#b388ff",
        "Exfiltration":  "#ff4081"
    };

    function initCharts() {
        // Packet rate line chart
        const ctxLine = document.getElementById("packetChart").getContext("2d");
        const gradient = ctxLine.createLinearGradient(0, 0, 0, 200);
        gradient.addColorStop(0, "rgba(79, 195, 247, 0.25)");
        gradient.addColorStop(1, "rgba(79, 195, 247, 0.0)");

        packetChart = new Chart(ctxLine, {
            type: "line",
            data: {
                labels: [],
                datasets: [{
                    label: "Packets/sec",
                    data: [],
                    borderColor: "#4fc3f7",
                    backgroundColor: gradient,
                    borderWidth: 2,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    fill: true,
                    tension: 0.4,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 400 },
                plugins: { legend: { display: false } },
                scales: {
                    x: {
                        display: true,
                        grid: { color: "rgba(255,255,255,0.04)" },
                        ticks: { color: "#5c6bc0", maxTicksLimit: 8, font: { size: 10 } }
                    },
                    y: {
                        display: true,
                        beginAtZero: true,
                        grid: { color: "rgba(255,255,255,0.04)" },
                        ticks: { color: "#5c6bc0", font: { size: 10 } }
                    }
                }
            }
        });

        // Attack class donut chart
        const ctxDonut = document.getElementById("classChart").getContext("2d");
        classChart = new Chart(ctxDonut, {
            type: "doughnut",
            data: {
                labels: Object.keys(classData),
                datasets: [{
                    data: Object.values(classData),
                    backgroundColor: Object.keys(classData).map(k => chartColors[k]),
                    borderWidth: 0,
                    hoverOffset: 8,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                cutout: "65%",
                animation: { duration: 400 },
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: {
                            color: "#9fa8da",
                            padding: 14,
                            font: { size: 11, family: "'Inter', sans-serif" },
                            usePointStyle: true,
                            pointStyleWidth: 10,
                        }
                    }
                }
            }
        });
    }

    // ─── Formatting ───
    function formatUptime(seconds) {
        const h = Math.floor(seconds / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        const s = Math.floor(seconds % 60);
        return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
    }

    function formatNumber(n) {
        if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
        if (n >= 1_000)     return (n / 1_000).toFixed(1) + "K";
        return String(n);
    }

    function timeLabel() {
        const d = new Date();
        return `${String(d.getHours()).padStart(2,"0")}:${String(d.getMinutes()).padStart(2,"0")}:${String(d.getSeconds()).padStart(2,"0")}`;
    }

    // ─── Stats polling ───
    let connected = false;

    async function fetchStats() {
        try {
            const resp = await fetch("/api/stats");
            if (!resp.ok) throw new Error(resp.statusText);
            const data = await resp.json();

            $totalPackets.textContent = formatNumber(data.total_packets);
            $totalAlerts.textContent  = formatNumber(data.total_alerts);
            $blockedCount.textContent = formatNumber(data.blocked_ips_count);
            $pps.textContent          = data.packets_per_sec;
            $uptime.textContent       = formatUptime(data.uptime_seconds);

            // Update packet rate chart
            ppsHistory.push(data.packets_per_sec);
            if (ppsHistory.length > CHART_MAX_POINTS) ppsHistory.shift();

            packetChart.data.labels = ppsHistory.map((_, i) => "");
            // Use time-based labels for last point
            const labels = packetChart.data.labels;
            if (labels.length > 0) labels[labels.length - 1] = timeLabel();
            packetChart.data.datasets[0].data = [...ppsHistory];
            packetChart.update("none");

            setConnected(true);
        } catch {
            setConnected(false);
        }
    }

    async function fetchBlocked() {
        try {
            const resp = await fetch("/api/blocked");
            if (!resp.ok) return;
            const ips = await resp.json();
            renderBlocked(ips);
        } catch { /* ignore */ }
    }

    function setConnected(state) {
        connected = state;
        if (state) {
            $statusBadge.classList.remove("offline");
            $statusText.textContent = "Live";
        } else {
            $statusBadge.classList.add("offline");
            $statusText.textContent = "Offline";
        }
    }

    // ─── Alert rendering ───
    let alertCount = 0;

    function addAlertToFeed(alert) {
        alertCount++;
        $feedCount.textContent = alertCount;

        // Remove empty placeholder
        const empty = $alertFeed.querySelector(".feed-empty");
        if (empty) empty.remove();

        const classSlug = (alert.attack_class || "unknown")
            .toLowerCase().replace(/\s+/g, "-");

        const el = document.createElement("div");
        el.className = "alert-item";
        el.innerHTML = `
            <span class="alert-class ${classSlug}">${escapeHtml(alert.attack_class || "Unknown")}</span>
            <span class="alert-details">${escapeHtml(alert.src_ip || "?")} → ${escapeHtml(alert.dst_ip || "?")}</span>
            <span class="alert-confidence" style="color:${confidenceColor(alert.confidence)}">${(alert.confidence * 100).toFixed(1)}%</span>
        `;

        $alertFeed.prepend(el);

        // Limit feed size
        while ($alertFeed.children.length > MAX_FEED_ITEMS) {
            $alertFeed.removeChild($alertFeed.lastChild);
        }

        // Update class distribution
        const cls = alert.attack_class;
        if (cls && cls in classData) {
            classData[cls]++;
            classChart.data.datasets[0].data = Object.values(classData);
            classChart.update("none");
        }
    }

    function renderBlocked(ips) {
        if (!ips || ips.length === 0) return;
        const empty = $blockedList.querySelector(".feed-empty");
        if (empty) empty.remove();

        // Rebuild
        $blockedList.innerHTML = "";
        ips.forEach(ip => {
            const el = document.createElement("div");
            el.className = "blocked-item";
            el.textContent = ip;
            $blockedList.appendChild(el);
        });
    }

    function confidenceColor(c) {
        if (c >= 0.9) return "#ff5252";
        if (c >= 0.7) return "#ffab40";
        return "#4fc3f7";
    }

    function escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

    // ─── WebSocket ───
    function connectWS() {
        const proto = location.protocol === "https:" ? "wss:" : "ws:";
        const ws = new WebSocket(`${proto}//${location.host}/ws/live`);

        ws.onopen = () => setConnected(true);

        ws.onmessage = (event) => {
            try {
                const alert = JSON.parse(event.data);
                addAlertToFeed(alert);
            } catch { /* ignore */ }
        };

        ws.onclose = () => {
            setConnected(false);
            setTimeout(connectWS, 3000); // auto-reconnect
        };

        ws.onerror = () => ws.close();
    }

    // ─── Fetch initial alerts ───
    async function fetchInitialAlerts() {
        try {
            const resp = await fetch("/api/alerts?limit=50");
            if (!resp.ok) return;
            const alerts = await resp.json();
            // Alerts are newest-first, render in reverse so newest ends up on top
            alerts.reverse().forEach(a => addAlertToFeed(a));
        } catch { /* ignore */ }
    }

    // ─── Init ───
    function init() {
        initCharts();
        fetchStats();
        fetchInitialAlerts();
        fetchBlocked();
        connectWS();

        setInterval(fetchStats, POLL_INTERVAL);
        setInterval(fetchBlocked, POLL_INTERVAL * 3);
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
