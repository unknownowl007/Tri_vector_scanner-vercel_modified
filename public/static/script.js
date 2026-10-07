let currentScanReport = null;

document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initEventListeners();
});

function initTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    
    tabBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            const targetId = e.currentTarget.getAttribute('data-target');
            activateTab(targetId);
        });

        btn.addEventListener('keydown', (event) => {
            const buttons = Array.from(tabBtns);
            const currentIndex = buttons.indexOf(event.currentTarget);
            let nextIndex;
            if (event.key === 'ArrowRight') nextIndex = (currentIndex + 1) % buttons.length;
            else if (event.key === 'ArrowLeft') nextIndex = (currentIndex - 1 + buttons.length) % buttons.length;
            else if (event.key === 'Home') nextIndex = 0;
            else if (event.key === 'End') nextIndex = buttons.length - 1;
            else return;

            event.preventDefault();
            const nextButton = buttons[nextIndex];
            activateTab(nextButton.dataset.target);
            nextButton.focus();
        });
    });
}

function activateTab(targetId) {
    document.querySelectorAll('.tab-content').forEach(panel => {
        const selected = panel.id === targetId;
        panel.classList.toggle('active', selected);
        panel.setAttribute('aria-hidden', String(!selected));
    });
    document.querySelectorAll('.tab-btn').forEach(button => {
        const selected = button.dataset.target === targetId;
        button.classList.toggle('active', selected);
        button.setAttribute('aria-selected', String(selected));
        button.tabIndex = selected ? 0 : -1;
    });
    updateTheme(targetId);
}

function updateTheme(tabId) {
    const root = document.documentElement;
    const themes = {
        'url-tab': { color: '#38bdf8', glow: 'rgba(56, 189, 248, 0.25)', bg: 'rgba(56, 189, 248, 0.05)' },
        'qr-tab':  { color: '#c084fc', glow: 'rgba(192, 132, 252, 0.25)', bg: 'rgba(192, 132, 252, 0.05)' },
        'pwd-tab': { color: '#34d399', glow: 'rgba(52, 211, 153, 0.25)', bg: 'rgba(52, 211, 153, 0.05)' },
        'enhanced-tab': { color: '#a78bfa', glow: 'rgba(167, 139, 250, 0.25)', bg: 'rgba(167, 139, 250, 0.05)' },
        'domain-tab': { color: '#fbbf24', glow: 'rgba(251, 191, 36, 0.25)', bg: 'rgba(251, 191, 36, 0.05)' },
        'speed-tab': { color: '#fb7185', glow: 'rgba(251, 113, 133, 0.25)', bg: 'rgba(251, 113, 133, 0.05)' }
    };

    if (themes[tabId]) {
        root.style.setProperty('--theme-color', themes[tabId].color); 
        root.style.setProperty('--theme-glow', themes[tabId].glow);
        root.style.setProperty('--theme-bg', themes[tabId].bg);
    }
}

function initEventListeners() {
    document.getElementById('toggle-icon').addEventListener('click', togglePasswordVisibility);
    document.getElementById('btn-scan-url').addEventListener('click', handleUrlScan);
    document.getElementById('btn-scan-qr').addEventListener('click', handleQrScan);
    document.getElementById('btn-check-pwd').addEventListener('click', handlePasswordCheck);
    document.getElementById('btn-scan-enhanced').addEventListener('click', handleEnhancedUrlScan);
    document.getElementById('btn-check-ssl').addEventListener('click', handleSslCheck);
    document.getElementById('btn-check-whois').addEventListener('click', handleWhoisLookup);
    document.getElementById('btn-lookup-ip').addEventListener('click', handleIpLookup);
    document.getElementById('btn-speed-test').addEventListener('click', handleSpeedTest);
    document.getElementById('btn-check-redirects').addEventListener('click', handleRedirectAnalysis);
    document.getElementById('btn-check-lookalike').addEventListener('click', handleLookalikeCheck);
    document.getElementById('url-input').addEventListener('keydown', submitOnEnter(handleUrlScan));
    document.getElementById('url-input').addEventListener('input', () => {
        currentScanReport = null;
    });
    document.getElementById('enhanced-url-input').addEventListener('keydown', submitOnEnter(handleEnhancedUrlScan));
    document.getElementById('ip-lookup-input').addEventListener('keydown', submitOnEnter(handleIpLookup));
}

function submitOnEnter(handler) {
    return event => {
        if (event.key === 'Enter') {
            event.preventDefault();
            handler();
        }
    };
}

function togglePasswordVisibility() {
    const pwdInput = document.getElementById('pwd-input');
    const toggleIcon = document.getElementById('toggle-icon');
    
    if (pwdInput.type === 'password') {
        pwdInput.type = 'text';
        toggleIcon.textContent = '🙈'; 
    } else {
        pwdInput.type = 'password';
        toggleIcon.textContent = '👁️'; 
    }
}

async function handleUrlScan() {
    const url = document.getElementById('url-input').value;
    const box = document.getElementById('url-result');
    box.style.display = 'none';

    try {
        const res = await fetch('/api/scan/url', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ url: url })
        });
        const json = await res.json();

        if (res.ok) {
            const data = json.data;
            box.className = 'result-box ' + (data.is_phishing ? 'alert-danger' : 'alert-success');
            window.ScanHistory.add({
                type: 'URL scan',
                target: url,
                result: data.is_phishing ? 'Phishing detected by model' : 'Not detected by model',
                danger: data.is_phishing,
                confidence: data.confidence
            });
            currentScanReport = {
                report_type: 'URL security scan',
                scanned_at: new Date().toISOString(),
                url,
                verdict: data.is_phishing ? 'Phishing detected by model' : 'Phishing not detected by model',
                confidence_percent: data.confidence,
                model: data.model,
                explanation: data.explanation,
                known_phishing_context: data.known_phishing || null
            };
            renderUrlScanResults(box, data);
        } else {
            showError(box, json.message);
        }
        box.style.display = 'block';
    } catch (err) {
        showError(box, "Network error occurred.");
    }
}

function renderUrlScanResults(box, data) {
    box.replaceChildren();
    const verdict = document.createElement('strong');
    verdict.textContent = data.is_phishing ? '🚨 PHISHING DETECTED BY MODEL' : '✅ MODEL DID NOT DETECT PHISHING';
    box.appendChild(verdict);
    box.appendChild(document.createElement('br'));
    const confidence = document.createElement('span');
    confidence.className = 'tool-description';
    confidence.textContent = `Confidence: ${data.confidence}% · ${data.model || 'URL model'}`;
    box.appendChild(confidence);
    renderExplanation(box, data.explanation);
    if (data.known_phishing && data.known_phishing.listed) {
        const context = document.createElement('p');
        context.className = 'tool-description';
        context.textContent = `Supplemental historical dataset match: ${data.known_phishing.source}. The model determines the verdict.`;
        box.appendChild(context);
    }
    appendReportButton(box);
    box.style.display = 'block';
}

function renderExplanation(box, explanation) {
    if (!explanation) return;
    const heading = document.createElement('h3');
    heading.className = 'explanation-heading';
    heading.textContent = 'Why the model scored this URL';
    box.appendChild(heading);
    if (typeof explanation.baseline_phishing_probability === 'number') {
        const baseline = document.createElement('p');
        baseline.className = 'tool-description';
        baseline.textContent = `Average model baseline: ${explanation.baseline_phishing_probability}% phishing probability.`;
        box.appendChild(baseline);
    }
    if (explanation.signals && explanation.signals.length) {
        const list = document.createElement('ul');
        list.className = 'explanation-list';
        explanation.signals.forEach(signal => {
            const item = document.createElement('li');
            item.textContent = `${signal.feature} (${signal.value}) ${signal.effect} the phishing score; impact ${signal.impact} percentage points.`;
            list.appendChild(item);
        });
        box.appendChild(list);
    } else {
        if (!explanation.note) {
            const note = document.createElement('p');
            note.className = 'tool-description';
            note.textContent = 'No individual model signals were available for this scan.';
            box.appendChild(note);
        }
    }
    if (explanation.note) {
        const note = document.createElement('p');
        note.className = 'tool-description';
        note.textContent = explanation.note;
        box.appendChild(note);
    }
}

function appendReportButton(box) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'secondary-btn report-button';
    button.textContent = 'Download scan report (JSON)';
    button.addEventListener('click', downloadScanReport);
    box.appendChild(button);
}

function downloadScanReport() {
    if (!currentScanReport) return;
    const file = new Blob([JSON.stringify(currentScanReport, null, 2)], {type: 'application/json'});
    const link = document.createElement('a');
    const reportUrl = URL.createObjectURL(file);
    link.href = reportUrl;
    link.download = 'tri-vector-scan-report.json';
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(reportUrl), 60000);
}

async function handleRedirectAnalysis() {
    const url = document.getElementById('url-input').value;
    const box = document.getElementById('redirect-result');
    await runUrlAnalysis('/api/analyze/redirects', {url}, box, 'Analyzing redirects...', data => {
        box.className = 'result-box alert-warning';
        renderDetails(box, 'Redirect chain', [
            ['Redirects', String(data.redirect_count)],
            ['Final URL', data.final_url]
        ]);
        const list = document.createElement('ol');
        list.className = 'redirect-list';
        data.chain.forEach(hop => {
            const item = document.createElement('li');
            item.textContent = `${hop.status} · ${hop.url}${hop.redirect_to ? ` → ${hop.redirect_to}` : ''}`;
            list.appendChild(item);
        });
        box.appendChild(list);
        currentScanReport = {...(currentScanReport || {report_type: 'URL analysis', scanned_at: new Date().toISOString(), url}), redirect_chain: data};
        appendReportButton(box);
        window.ScanHistory.add({
            type: 'Redirect-chain analysis',
            target: url,
            result: `${data.redirect_count} redirects`,
            danger: data.redirect_count > 2
        });
    });
}

async function handleLookalikeCheck() {
    const url = document.getElementById('url-input').value;
    const box = document.getElementById('lookalike-result');
    await runUrlAnalysis('/api/analyze/lookalike', {domain: url}, box, 'Checking domain similarity...', data => {
        box.className = 'result-box ' + (data.suspicious ? 'alert-warning' : 'alert-success');
        box.replaceChildren();
        const summary = document.createElement('strong');
        summary.textContent = data.message;
        box.appendChild(summary);
        const list = document.createElement('ul');
        list.className = 'explanation-list';
        data.matches.forEach(match => {
            const item = document.createElement('li');
            item.textContent = `${match.lookalike_label} resembles ${match.brand} (${match.similarity}% similarity; official domain: ${match.official_domain}).`;
            list.appendChild(item);
        });
        if (data.matches.length) box.appendChild(list);
        currentScanReport = {...(currentScanReport || {report_type: 'URL analysis', scanned_at: new Date().toISOString(), url}), lookalike_check: data};
        appendReportButton(box);
        window.ScanHistory.add({
            type: 'Lookalike-domain check',
            target: data.domain,
            result: data.suspicious ? 'Possible brand impersonation' : 'No close brand match',
            danger: data.suspicious
        });
    });
}

async function runUrlAnalysis(endpoint, payload, box, waitingText, renderResults) {
    box.className = 'result-box alert-warning';
    box.textContent = waitingText;
    box.style.display = 'block';
    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.message || 'The analysis could not be completed.');
        renderResults(result.data);
        box.style.display = 'block';
    } catch (error) {
        showSafeError(box, error.message || 'Network error occurred.');
    }
}

async function handleQrScan() {
    const fileInput = document.getElementById('qr-input');
    const box = document.getElementById('qr-result');
    box.style.display = 'none';

    if (!fileInput.files[0]) {
        showError(box, 'No image file selected.');
        return;
    }

    const formData = new FormData();
    formData.append('qr_image', fileInput.files[0]);

    try {
        const res = await fetch('/api/scan/qr', {
            method: 'POST',
            body: formData
        });
        const json = await res.json();

        if (res.ok) {
            const data = json.data;
            const isListed = data.known_phishing && data.known_phishing.listed;
            box.className = 'result-box ' + (data.is_phishing ? 'alert-danger' : 'alert-success');
            window.ScanHistory.add({
                type: 'QR scan',
                target: json.extracted_url,
                result: data.is_phishing ? 'Phishing detected by model' : 'Not detected by model',
                danger: data.is_phishing,
                confidence: data.confidence
            });
            box.innerHTML = `
                <div style="margin-bottom: 10px; color: var(--text-muted)">
                    <strong>Decoded Object:</strong><br><code style="word-break: break-all; color: #f8fafc;">${escapeHtml(json.extracted_url)}</code>
                </div>
                <strong>${data.is_phishing ? '🚨 PHISHING DETECTED BY MODEL' : '✅ MODEL DID NOT DETECT PHISHING'}</strong><br>
                <span style="color:var(--text-muted)">Confidence: ${data.confidence}%</span>
                ${isListed ? renderKnownPhishingStatus(data.known_phishing) : ''}
            `;
        } else {
            showError(box, json.message);
        }
        box.style.display = 'block';
    } catch (err) {
        showError(box, "Network error occurred.");
    }
}

async function handlePasswordCheck() {
    const password = document.getElementById('pwd-input').value;
    const box = document.getElementById('pwd-result');
    box.style.display = 'none';

    try {
        const res = await fetch('/api/check/password', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ password: password })
        });
        const json = await res.json();

        if (res.ok) {
            renderPasswordResults(box, json);
        } else {
            showError(box, json.message);
        }
        box.style.display = 'block';
    } catch (err) {
        showError(box, "Network error occurred.");
    }
}

function renderPasswordResults(box, data) {
    const labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"];
    const colors = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#10b981"]; 
    const fillWidth = (data.score + 1) * 20;

    const breachText = data.breach_count > 0 
        ? `<span style="color: #fca5a5; font-weight: bold;">⚠️ Leaked in ${data.breach_count.toLocaleString()} data breaches</span>`
        : `<span style="color: #86efac; font-weight: bold;">🛡️ No known leaks detected</span>`;

    const suggestions = data.suggestions.length > 0 
        ? "<ul>" + data.suggestions.map(s => `<li>${s}</li>`).join('') + "</ul>" 
        : "";

    box.className = 'result-box alert-warning'; 
    box.innerHTML = `
        <strong style="color:#f8fafc;">Strength Rating:</strong> ${labels[data.score]}
        <div class="meter">
            <div class="meter-fill" style="width: ${fillWidth}%; background-color: ${colors[data.score]};"></div>
        </div><br>
        <strong style="color:#f8fafc;">Breach Status:</strong> ${breachText}<br><br>
        ${data.warning ? `<strong style="color: #fca5a5;">Warning:</strong> ${data.warning}<br>` : ''}
        ${suggestions ? `<strong style="color:#f8fafc;">Suggestions:</strong> ${suggestions}` : ''}
    `;
}

function showError(boxElement, message) {
    boxElement.className = 'result-box alert-warning';
    boxElement.innerHTML = message;
    boxElement.style.display = 'block';
}

async function handleEnhancedUrlScan() {
    const url = document.getElementById('enhanced-url-input').value;
    const box = document.getElementById('enhanced-url-result');
    box.style.display = 'none';
    try {
        const response = await fetch('/api/scan/url/enhanced', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url})
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.message || 'The enhanced scan could not be completed.');
        const data = result.data;
        const isListed = data.known_phishing && data.known_phishing.listed;
        box.className = 'result-box ' + (data.is_phishing ? 'alert-danger' : 'alert-success');
        window.ScanHistory.add({
            type: 'Enhanced URL scan',
            target: url,
            result: data.is_phishing ? 'Phishing detected by model' : 'Not detected by model',
            danger: data.is_phishing,
            confidence: data.confidence
        });
        renderDetails(box, data.is_phishing ? 'Phishing detected by model' : 'Model did not detect phishing', [
            ['Confidence', `${data.confidence}%`],
            ['Signals analyzed', String(data.feature_count)]
        ]);
        currentScanReport = {
            report_type: 'Enhanced URL security scan',
            scanned_at: new Date().toISOString(),
            url,
            verdict: data.is_phishing ? 'Phishing detected by model' : 'Phishing not detected by model',
            confidence_percent: data.confidence,
            model: 'enhanced',
            explanation: data.explanation,
            known_phishing_context: data.known_phishing || null
        };
        renderExplanation(box, data.explanation);
        appendReportButton(box);
        if (isListed) box.insertAdjacentHTML('beforeend', renderKnownPhishingStatus(data.known_phishing));
        box.style.display = 'block';
    } catch (error) {
        showSafeError(box, error.message || 'Network error occurred.');
    }
}

async function handleSslCheck() {
    const box = document.getElementById('ssl-result');
    await runDomainCheck('/api/domain/ssl', box, document.getElementById('btn-check-ssl'), renderSslResults);
}

async function handleWhoisLookup() {
    const box = document.getElementById('whois-result');
    await runDomainCheck('/api/domain/whois', box, document.getElementById('btn-check-whois'), renderWhoisResults);
}

async function handleIpLookup() {
    const address = document.getElementById('ip-lookup-input').value.trim();
    const box = document.getElementById('ip-lookup-result');
    const button = document.getElementById('btn-lookup-ip');
    box.style.display = 'none';
    button.disabled = true;
    button.textContent = 'Looking up...';
    try {
        const response = await fetch('/api/domain/ip-lookup', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip: address})
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.message || 'The IP lookup could not be completed.');
        const data = result.data;
        box.className = 'result-box alert-success';
        renderDetails(box, `Public IP details · ${data.ip}`, [
            ['IP version', data.version || 'Not provided'],
            ['Country', data.country || 'Not provided'],
            ['Region', data.region || 'Not provided'],
            ['City', data.city || 'Not provided'],
            ['Coordinates', data.latitude == null || data.longitude == null
                ? 'Not provided'
                : `${data.latitude}, ${data.longitude}`],
            ['ISP', data.isp || 'Not provided'],
            ['Organization', data.organization || 'Not provided'],
            ['ASN', data.asn || 'Not provided'],
            ['Lookup provider', data.provider]
        ]);
        window.ScanHistory.add({
            type: 'Manual IP lookup',
            target: data.ip,
            result: [data.city, data.country].filter(Boolean).join(', ') || 'Public IP details found'
        });
    } catch (error) {
        showSafeError(box, error.message || 'The IP lookup could not be completed.');
    } finally {
        button.disabled = false;
        button.textContent = 'Look up IP address';
        box.style.display = 'block';
    }
}

async function runDomainCheck(endpoint, box, button, renderResults) {
    box.style.display = 'none';
    button.disabled = true;
    button.textContent = 'Checking...';
    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({domain: document.getElementById('domain-input').value})
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.message || 'The lookup could not be completed.');
        renderResults(box, result.data);
        window.ScanHistory.add({
            type: endpoint.endsWith('/ssl') ? 'SSL certificate check' : 'WHOIS/RDAP lookup',
            target: document.getElementById('domain-input').value,
            result: endpoint.endsWith('/ssl')
                ? (result.data.valid ? 'Certificate valid' : 'Certificate validation failed')
                : 'Registration details found',
            danger: endpoint.endsWith('/ssl') && !result.data.valid
        });
    } catch (error) {
        showSafeError(box, error.message || 'Network error occurred.');
    } finally {
        button.disabled = false;
        button.textContent = endpoint.endsWith('/ssl') ? 'Validate SSL' : 'WHOIS / RDAP';
        box.style.display = 'block';
    }
}

function renderSslResults(box, data) {
    box.className = 'result-box ' + (data.valid ? 'alert-success' : 'alert-danger');
    renderDetails(box, data.valid ? 'Certificate is valid' : 'Certificate validation failed', data.valid
        ? [
            ['Domain', data.hostname],
            ['Issuer', data.issuer || 'Not provided'],
            ['Expires', formatDate(data.expires_at)],
            ['Days remaining', String(data.days_remaining)]
        ]
        : [['Details', data.message]]);
}

function renderWhoisResults(box, data) {
    box.className = 'result-box alert-success';
    renderDetails(box, 'Registration details', [
        ['Domain', data.domain],
        ['Registrar', data.registrar || 'Not disclosed'],
        ['Created', formatDate(data.created_at)],
        ['Last updated', formatDate(data.updated_at)],
        ['Expires', formatDate(data.expires_at)],
        ['Status', data.status.length ? data.status.join(', ') : 'Not disclosed']
    ]);
}

function renderDetails(box, heading, values) {
    box.replaceChildren();
    const title = document.createElement('strong');
    title.textContent = heading;
    box.appendChild(title);
    const list = document.createElement('dl');
    list.className = 'details-list';
    values.forEach(([label, value]) => {
        const term = document.createElement('dt');
        term.textContent = label;
        const description = document.createElement('dd');
        description.textContent = value;
        list.append(term, description);
    });
    box.appendChild(list);
}

function formatDate(value) {
    if (!value) return 'Not disclosed';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function renderKnownPhishingStatus(result) {
    if (!result || !result.listed) return '';
    return `<p class="tool-description"><strong>Supplemental historical dataset match:</strong> ${escapeHtml(result.source)}. The verdict above is from the AI model.</p>`;
}

function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, character => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[character]);
}

async function handleSpeedTest() {
    const button = document.getElementById('btn-speed-test');
    const box = document.getElementById('speed-result');
    box.className = 'result-box alert-warning';
    box.textContent = 'Measuring internet download speed...';
    box.style.display = 'block';
    button.disabled = true;
    button.textContent = 'Testing...';

    try {
        const downloadStart = performance.now();
        const downloadBytes = 10 * 1024 * 1024;
        const downloadResponse = await fetch(
            `https://speed.cloudflare.com/__down?bytes=${downloadBytes}&test=${Date.now()}`,
            {cache: 'no-store'}
        );
        if (!downloadResponse.ok) throw new Error('Download test could not be completed.');
        const downloaded = await downloadResponse.arrayBuffer();
        const downloadSeconds = Math.max((performance.now() - downloadStart) / 1000, 0.001);

        box.textContent = 'Measuring internet upload speed...';
        const upload = new Uint8Array(5 * 1024 * 1024);
        const uploadStart = performance.now();
        const uploadResponse = await fetch('https://speed.cloudflare.com/__up', {
            method: 'POST',
            headers: {'Content-Type': 'application/octet-stream'},
            body: upload,
            cache: 'no-store'
        });
        if (!uploadResponse.ok) throw new Error('Upload test could not be completed.');
        const uploadSeconds = Math.max((performance.now() - uploadStart) / 1000, 0.001);
        box.className = 'result-box alert-success';
        renderDetails(box, 'Internet speed test complete', [
            ['Download', `${(downloaded.byteLength * 8 / downloadSeconds / 1000000).toFixed(2)} Mbps`],
            ['Upload', `${(upload.byteLength * 8 / uploadSeconds / 1000000).toFixed(2)} Mbps`],
            ['Test network', 'Cloudflare nearby test server']
        ]);
        box.style.display = 'block';
    } catch (error) {
        showSafeError(box, error.message || 'Network error occurred.');
    } finally {
        button.disabled = false;
        button.textContent = 'Test internet speed';
    }
}

function showSafeError(box, message) {
    box.className = 'result-box alert-warning';
    box.textContent = message;
    box.style.display = 'block';
}