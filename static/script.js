document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('url-form');
    const input = document.getElementById('url-input');
    const btn = document.getElementById('scan-btn');
    const btnText = document.querySelector('.btn-text');
    const spinner = document.getElementById('loading-spinner');
    
    const resultsDashboard = document.getElementById('results-dashboard');
    const errorBox = document.getElementById('error-container');
    const errorText = document.getElementById('error-text');

    // Stats UI
    const riskProgress = document.getElementById('risk-progress');
    const riskScoreTxt = document.getElementById('risk-score');
    const overallStatus = document.getElementById('overall-status');
    const resultUrl = document.getElementById('result-url');
    
    // Lists UI
    const reasonsList = document.getElementById('reasons-list');
    const noThreatsMsg = document.getElementById('no-threats-msg');
    const featuresGrid = document.getElementById('features-grid');

    const CIRCUMFERENCE = 283; // 2 * pi * 45 (radius of circle)

    function updateRiskMeter(score) {
        // SVG Circle animation
        const offset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;
        riskProgress.style.strokeDashoffset = offset;
        
        // Counter animation
        let current = 0;
        const totalFrames = 30;
        let frame = 0;
        
        const counter = setInterval(() => {
            frame++;
            current = score * (frame / totalFrames);
            riskScoreTxt.innerText = Math.round(current);
            if (frame >= totalFrames) {
                clearInterval(counter);
                riskScoreTxt.innerText = Math.round(score);
            }
        }, 15);
    }

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = input.value.trim();
        if (!url) return;

        // Reset & Loading State
        errorBox.classList.add('hidden');
        resultsDashboard.classList.add('hidden');
        resultsDashboard.className = 'results-dashboard hidden'; // Reset classes
        riskProgress.style.strokeDashoffset = CIRCUMFERENCE;
        riskScoreTxt.innerText = "0";
        reasonsList.innerHTML = '';
        featuresGrid.innerHTML = '';
        
        btn.disabled = true;
        btnText.classList.add('hidden');
        spinner.classList.remove('hidden');

        try {
            await new Promise(resolve => setTimeout(resolve, 600)); // UX delay

            const response = await fetch('/predict', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });

            const data = await response.json();
            if (!response.ok) throw new Error(data.error || 'Server error occurred');

            // Render Results
            resultUrl.textContent = data.url;
            overallStatus.textContent = data.status.toUpperCase();
            
            // Set Color Theme based on Risk
            if (data.is_safe) {
                resultsDashboard.classList.add('is-safe');
            } else if (data.risk_score > 60) {
                resultsDashboard.classList.add('is-phishing');
            } else {
                resultsDashboard.classList.add('is-suspicious');
            }

            // Animate Meter
            updateRiskMeter(data.risk_score);

            // Populate Threat Matrix (Reasons)
            if (data.reasons && data.reasons.length > 0) {
                noThreatsMsg.classList.add('hidden');
                data.reasons.forEach(reason => {
                    const li = document.createElement('li');
                    li.className = `reason-item ${reason.type}`;
                    
                    let icon = 'ℹ️';
                    if (reason.type === 'critical') icon = '⛔';
                    if (reason.type === 'warning') icon = '⚠️';
                    
                    li.innerHTML = `<span class="reason-icon">${icon}</span> <span class="reason-text">${reason.msg}</span>`;
                    reasonsList.appendChild(li);
                });
            } else {
                noThreatsMsg.classList.remove('hidden');
            }

            // Populate Features Telemetry
            const fmap = [
                { id: 'entropy', label: 'Entropy Score', fmt: v => v.toFixed(2), riskCheck: v => v > 4.5 },
                { id: 'length', label: 'URL Length', fmt: v => v, riskCheck: v => v > 75 },
                { id: 'num_subdomains', label: 'Subdomains', fmt: v => v, riskCheck: v => v >= 3 },
                { id: 'is_typosquatting', label: 'Typosquatting', fmt: v => v ? 'DETECTED' : 'CLEAN', riskCheck: v => v === 1 },
                { id: 'has_non_ascii', label: 'Homograph/Punycode', fmt: v => v ? 'DETECTED' : 'CLEAN', riskCheck: v => v === 1 },
                { id: 'is_shortener', label: 'URL Shortener', fmt: v => v ? 'DETECTED' : 'CLEAN', riskCheck: v => v === 1 },
                { id: 'has_ip', label: 'IP Host', fmt: v => v ? 'IP USED' : 'CLEAN', riskCheck: v => v === 1 },
                { id: 'suspicious_words_count', label: 'Target Keywords', fmt: v => v, riskCheck: v => v > 0 },
                { id: 'is_https', label: 'SSL Protocol', fmt: v => v ? 'HTTPS' : 'HTTP', riskCheck: v => v === 0 }
            ];

            fmap.forEach(f => {
                if (data.features[f.id] !== undefined) {
                    const val = data.features[f.id];
                    const div = document.createElement('div');
                    div.className = 'feature-item';
                    
                    const isRisk = f.riskCheck(val);
                    const valClass = isRisk ? 'risk' : 'safe';
                    
                    div.innerHTML = `
                        <span class="feature-label">${f.label}</span>
                        <span class="feature-val ${valClass}">${f.fmt(val)}</span>
                    `;
                    featuresGrid.appendChild(div);
                }
            });

            // Show dashboard
            resultsDashboard.classList.remove('hidden');

        } catch (err) {
            errorText.textContent = err.message;
            errorBox.classList.remove('hidden');
        } finally {
            btn.disabled = false;
            btnText.classList.remove('hidden');
            spinner.classList.add('hidden');
        }
    });
});
