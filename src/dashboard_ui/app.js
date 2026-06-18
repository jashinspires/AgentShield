// AgentShield Dashboard interactive scripts
document.addEventListener("DOMContentLoaded", () => {
    // API elements
    const logsTbody = document.getElementById("logs-tbody");
    const refreshLogsBtn = document.getElementById("refresh-logs-btn");
    const refreshGraphBtn = document.getElementById("refresh-graph-btn");
    
    // Canvas dimensions setup
    const canvas = document.getElementById("graph-canvas");
    const ctx = canvas.getContext("2d");
    
    let nodes = [];
    let links = [];
    let selectedNode = null;
    let draggedNode = null;
    
    // Resize handler
    function resizeCanvas() {
        const rect = canvas.parentElement.getBoundingClientRect();
        canvas.width = rect.width;
        canvas.height = rect.height;
    }
    
    window.addEventListener("resize", resizeCanvas);
    resizeCanvas();

    // Fetch and populate audit logs
    async function loadLogs() {
        try {
            logsTbody.innerHTML = `<tr><td colspan="6" class="placeholder-row">Loading audits...</td></tr>`;
            const res = await fetch("/api/logs");
            const data = await res.json();
            
            if (data.length === 0) {
                logsTbody.innerHTML = `<tr><td colspan="6" class="placeholder-row">No command interceptions recorded yet.</td></tr>`;
                return;
            }
            
            logsTbody.innerHTML = "";
            data.forEach(log => {
                const tr = document.createElement("tr");
                
                // Format Timestamp
                const date = new Date(log.timestamp);
                const formattedTime = date.toLocaleTimeString() + " " + date.toLocaleDateString();
                
                // Format Verdict badge
                const verdictLower = log.verdict.toLowerCase();
                const badgeClass = `badge badge-${verdictLower}`;
                
                // Format Status
                const statusText = log.exit_code === 0 ? "SUCCESS" : "FAILED / BLOCKED";
                const statusClass = log.exit_code === 0 ? "allow-text" : "block-text";
                
                tr.innerHTML = `
                    <td>${formattedTime}</td>
                    <td><code>${escapeHtml(log.raw_command)}</code></td>
                    <td><code>${escapeHtml(log.normalized_command)}</code></td>
                    <td><span class="${badgeClass}">${log.verdict}</span></td>
                    <td>${escapeHtml(log.reason)}</td>
                    <td class="${statusClass}" style="font-weight: 600;">${statusText}</td>
                `;
                logsTbody.appendChild(tr);
            });
        } catch (e) {
            logsTbody.innerHTML = `<tr><td colspan="6" class="placeholder-row error-text">Error loading logs: ${e.message}</td></tr>`;
        }
    }

    // Escape helper
    function escapeHtml(str) {
        if (!str) return "";
        return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }

    // Fetch call-graph data
    async function loadGraph() {
        try {
            const res = await fetch("/api/graph");
            const data = await res.json();
            
            const graphEmpty = document.getElementById("graph-empty");
            if (!data.nodes || data.nodes.length === 0) {
                graphEmpty.classList.remove("hidden");
                nodes = [];
                links = [];
                return;
            }
            
            graphEmpty.classList.add("hidden");
            
            // Map old positions to preserve layout if refreshing
            const posMap = {};
            nodes.forEach(n => {
                posMap[n.id] = { x: n.x, y: n.y };
            });
            
            nodes = data.nodes.map(n => {
                const prev = posMap[n.id];
                return {
                    id: n.id,
                    label: n.label,
                    x: prev ? prev.x : canvas.width / 2 + (Math.random() - 0.5) * 100,
                    y: prev ? prev.y : canvas.height / 2 + (Math.random() - 0.5) * 100,
                    vx: 0,
                    vy: 0,
                    radius: 20 + (n.id.split('.').length * 2) // Larger radius for nested namespaces
                };
            });
            
            links = data.links;
        } catch (e) {
            console.error("Failed to load call graph data", e);
        }
    }

    // Custom Canvas Force-Directed Layout Simulation
    function updatePhysics() {
        const k = 0.05; // Spring constant
        const rep = 400; // Repulsion strength
        const centerGravity = 0.01;
        
        // Center of canvas
        const cx = canvas.width / 2;
        const cy = canvas.height / 2;
        
        // 1. Repulsion between all nodes
        for (let i = 0; i < nodes.length; i++) {
            let n1 = nodes[i];
            for (let j = i + 1; j < nodes.length; j++) {
                let n2 = nodes[j];
                let dx = n2.x - n1.x;
                let dy = n2.y - n1.y;
                let dist = Math.sqrt(dx * dx + dy * dy) || 1;
                
                if (dist < 250) {
                    let force = (rep * rep) / (dist * dist);
                    let fx = (dx / dist) * force;
                    let fy = (dy / dist) * force;
                    
                    n1.vx -= fx;
                    n1.vy -= fy;
                    n2.vx += fx;
                    n2.vy += fy;
                }
            }
        }
        
        // 2. Spring forces along links
        links.forEach(link => {
            const sNode = nodes.find(n => n.id === link.source);
            const tNode = nodes.find(n => n.id === link.target);
            
            if (sNode && tNode) {
                let dx = tNode.x - sNode.x;
                let dy = tNode.y - sNode.y;
                let dist = Math.sqrt(dx * dx + dy * dy) || 1;
                
                // Target length
                const restLength = 120;
                let force = (dist - restLength) * k;
                
                let fx = (dx / dist) * force;
                let fy = (dy / dist) * force;
                
                sNode.vx += fx;
                sNode.vy += fy;
                tNode.vx -= fx;
                tNode.vy -= fy;
            }
        });
        
        // 3. Update positions and apply damping / center pull
        nodes.forEach(node => {
            if (node === draggedNode) return;
            
            // Gravity pull to center
            node.vx += (cx - node.x) * centerGravity;
            node.vy += (cy - node.y) * centerGravity;
            
            node.x += node.vx;
            node.y += node.vy;
            
            // Damping friction
            node.vx *= 0.85;
            node.vy *= 0.85;
            
            // Constrain within borders
            node.x = Math.max(node.radius, Math.min(canvas.width - node.radius, node.x));
            node.y = Math.max(node.radius, Math.min(canvas.height - node.radius, node.y));
        });
    }

    // Render loop
    function draw() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        updatePhysics();
        
        // Draw Links
        ctx.strokeStyle = "rgba(99, 102, 241, 0.2)";
        ctx.lineWidth = 2;
        links.forEach(link => {
            const sNode = nodes.find(n => n.id === link.source);
            const tNode = nodes.find(n => n.id === link.target);
            if (sNode && tNode) {
                ctx.beginPath();
                ctx.moveTo(sNode.x, sNode.y);
                ctx.lineTo(tNode.x, tNode.y);
                ctx.stroke();
                
                // Draw arrow indicator
                const angle = Math.atan2(tNode.y - sNode.y, tNode.x - sNode.x);
                ctx.fillStyle = "rgba(99, 102, 241, 0.4)";
                ctx.beginPath();
                // Draw small arrow triangle along link
                const arrowX = tNode.x - tNode.radius * Math.cos(angle);
                const arrowY = tNode.y - tNode.radius * Math.sin(angle);
                ctx.arc(arrowX, arrowY, 4, 0, Math.PI * 2);
                ctx.fill();
            }
        });
        
        // Draw Nodes
        nodes.forEach(node => {
            const isHovered = (node === selectedNode);
            
            // Inner circle
            ctx.fillStyle = isHovered ? "rgba(99, 102, 241, 0.8)" : "rgba(255, 255, 255, 0.08)";
            ctx.strokeStyle = isHovered ? "#818CF8" : "rgba(255, 255, 255, 0.2)";
            ctx.lineWidth = isHovered ? 3 : 1;
            
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
            ctx.fill();
            ctx.stroke();
            
            // Label
            ctx.fillStyle = isHovered ? "#FFFFFF" : "#E5E7EB";
            ctx.font = isHovered ? "bold 11px Outfit, sans-serif" : "10px Outfit, sans-serif";
            ctx.textAlign = "center";
            ctx.fillText(node.label, node.x, node.y + 4);
            
            // Namespace hover indicator (above node)
            if (isHovered) {
                ctx.fillStyle = "#F3F4F6";
                ctx.font = "bold 9px monospace";
                ctx.fillText(node.id, node.x, node.y - node.radius - 8);
            }
        });
        
        requestAnimationFrame(draw);
    }

    // Interactivity
    canvas.addEventListener("mousemove", (e) => {
        const rect = canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        
        if (draggedNode) {
            draggedNode.x = mx;
            draggedNode.y = my;
            return;
        }
        
        // Find hovered node
        let found = null;
        for (let node of nodes) {
            const dx = node.x - mx;
            const dy = node.y - my;
            if (Math.sqrt(dx*dx + dy*dy) < node.radius) {
                found = node;
                break;
            }
        }
        selectedNode = found;
        canvas.style.cursor = found ? "grab" : "default";
    });

    canvas.addEventListener("mousedown", () => {
        if (selectedNode) {
            draggedNode = selectedNode;
            canvas.style.cursor = "grabbing";
        }
    });

    canvas.addEventListener("mouseup", () => {
        draggedNode = null;
        canvas.style.cursor = selectedNode ? "grab" : "default";
    });
    
    canvas.addEventListener("mouseleave", () => {
        draggedNode = null;
        selectedNode = null;
    });

    // Button actions
    refreshLogsBtn.addEventListener("click", loadLogs);
    refreshGraphBtn.addEventListener("click", loadGraph);

    // Initial load
    loadLogs();
    loadGraph();
    
    // Start canvas animation frame
    requestAnimationFrame(draw);
    
    // Auto refresh logs every 5 seconds
    setInterval(loadLogs, 5000);
});
