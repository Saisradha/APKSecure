const analyzerForm = document.getElementById('analyzerForm');
const packageInput = document.getElementById('packageInput');
const report = document.getElementById('report');
const reportTitle = document.getElementById('reportTitle');
const reportSubtitle = document.getElementById('reportSubtitle');
const scoreCard = document.getElementById('scoreCard');
const scoreValue = document.getElementById('scoreValue');
const scoreTag = document.getElementById('scoreTag');
const verdictText = document.getElementById('verdictText');
const analysisSummary = document.getElementById('analysisSummary');
const analysisTimestamp = document.getElementById('analysisTimestamp');
const usageAdvice = document.getElementById('usageAdvice');
const dangerPermList = document.getElementById('dangerPermList');
const normalPermList = document.getElementById('normalPermList');
const dataFlow = document.getElementById('dataFlow');
const mitigationList = document.getElementById('mitigationList');
const visualSummary = document.getElementById('visualSummary');
const feedList = document.getElementById('feedList');
const feedTimestamp = document.getElementById('feedTimestamp');

const FEED_REFRESH_MS = 15000;

const extractPackageName = (value) => {
  if (!value) return '';
  const trimmed = value.trim();
  try {
    const url = new URL(trimmed);
    const idParam = url.searchParams.get('id');
    if (idParam) return idParam;
  } catch (error) {
    // not a URL, fall through
  }

  const idMatch = trimmed.match(/id=([\w.\-]+)/i);
  if (idMatch) {
    return idMatch[1];
  }

  return trimmed;
};

const toggleReport = (visible) => {
  if (!report) return;
  report.hidden = !visible;
  if (visible) {
    report.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
};

const renderPermissionList = (element, items) => {
  if (!element) return;
  element.innerHTML = '';
  items.forEach((item) => {
    const li = document.createElement('li');
    li.innerHTML = `<code>${item.name}</code> — ${item.reason}`;
    element.appendChild(li);
  });
};

const renderDataFlow = (element, nodes) => {
  if (!element) return;
  element.innerHTML = '';
  nodes.forEach((node, index) => {
    const nodeEl = document.createElement('div');
    nodeEl.className = ['node', node.type || ''].join(' ').trim();
    nodeEl.innerHTML = `
      <span class="node-icon">${node.icon || '•'}</span>
      <span class="node-label">${node.label}</span>
    `;
    element.appendChild(nodeEl);

    if (index < nodes.length - 1) {
      const arrow = document.createElement('div');
      arrow.className = 'arrow';
      element.appendChild(arrow);
    }
  });
};

const renderMitigations = (element, items) => {
  if (!element) return;
  element.innerHTML = '';
  items.forEach((item) => {
    const li = document.createElement('li');
    li.textContent = item;
    element.appendChild(li);
  });
};

const applyRiskStyling = (level) => {
  if (!scoreCard) return;
  const normalised = (level || '').toLowerCase();
  scoreCard.classList.remove('risk-critical', 'risk-elevated', 'risk-guarded');
  const map = {
    critical: 'risk-critical',
    elevated: 'risk-elevated',
    guarded: 'risk-guarded',
  };
  if (map[normalised]) {
    scoreCard.classList.add(map[normalised]);
  }
};

const formatTimestamp = (isoString) => {
  try {
    const date = new Date(isoString);
    if (Number.isNaN(date.getTime())) return 'Timestamp unavailable';
    return `Generated ${date.toLocaleString()}`;
  } catch (error) {
    return 'Timestamp unavailable';
  }
};

const fetchScan = async (packageName) => {
  const response = await fetch(`/api/scan?package=${encodeURIComponent(packageName)}`);
  if (!response.ok) {
    throw new Error('Failed to retrieve scan data');
  }
  return response.json();
};

const fetchThreatFeed = async () => {
  try {
    const response = await fetch('/api/threats/latest');
    if (!response.ok) {
      throw new Error('Unable to load live threat feed');
    }
    const data = await response.json();
    if (!feedList) return;

    feedList.innerHTML = '';
    data.items.forEach((item) => {
      const li = document.createElement('li');
      li.className = 'feed-item';
      const levelClass = (item.risk_level || '').toLowerCase();
      li.innerHTML = `
        <div class="info">
          <strong>${item.package}</strong>
          <span>${item.summary || 'No summary available.'}</span>
        </div>
        <span class="feed-pill ${levelClass}">${item.risk_level || 'Unknown'} · ${Math.round(item.risk_score || 0)}</span>
      `;
      feedList.appendChild(li);
    });

    if (feedTimestamp) {
      feedTimestamp.textContent = data.generated_at ? `Updated ${new Date(data.generated_at).toLocaleTimeString()}` : 'Updated just now';
    }
  } catch (error) {
    if (feedTimestamp) {
      feedTimestamp.textContent = 'Live feed unavailable';
    }
  }
};

analyzerForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const pkg = extractPackageName(packageInput.value) || 'com.example.calculatorplus';
  toggleReport(false);

  try {
    const result = await fetchScan(pkg);

    reportTitle.textContent = result.app_name || result.package;
    if (reportSubtitle) {
      reportSubtitle.textContent = `Package ID: ${result.package}`;
    }

    scoreValue.textContent = result.risk_score_text || `Privacy Risk ${Math.round(result.risk_score || 0)}`;
    scoreTag.textContent = result.risk_level || 'Unknown';
    applyRiskStyling(result.risk_level);

    verdictText.textContent = result.verdict || 'Risk verdict unavailable.';
    analysisSummary.textContent = result.analysis_summary || '';
    analysisTimestamp.textContent = formatTimestamp(result.generated_at);
    if (usageAdvice) usageAdvice.textContent = result.usage_advice || '';

    renderPermissionList(dangerPermList, result.permissions?.dangerous || []);
    renderPermissionList(normalPermList, result.permissions?.normal || []);
    renderDataFlow(dataFlow, result.threat_flow || []);
    renderMitigations(mitigationList, result.actions || []);

    visualSummary.textContent = result.visual_summary || visualSummary.textContent;

    toggleReport(true);
    // Re-run animation for newly revealed elements
    requestAnimationFrame(() => {
      document.querySelectorAll('.anim').forEach((el) => el.classList.remove('in-view'));
      triggerReveal();
    });
  } catch (error) {
    toggleReport(false);
  }
});

if (feedList) {
  fetchThreatFeed();
  setInterval(fetchThreatFeed, FEED_REFRESH_MS);
}

// Subscribe to realtime server-sent events
try {
  const es = new EventSource('/events');
  es.onmessage = (ev) => {
    try {
      const msg = JSON.parse(ev.data || '{}');
      if (msg.type === 'scan' && msg.payload) {
        const p = msg.payload;
        // If the currently displayed package matches the message, update the report in place
        const currentPackageShown = reportSubtitle ? (reportSubtitle.textContent || '').replace('Package ID: ', '') : '';
        if (!currentPackageShown || currentPackageShown === p.package) {
          reportTitle.textContent = p.app_name || p.package;
          if (reportSubtitle) reportSubtitle.textContent = `Package ID: ${p.package}`;
          scoreValue.textContent = p.risk_score_text || `Privacy Risk ${Math.round(p.risk_score || 0)}`;
          scoreTag.textContent = p.risk_level || 'Unknown';
          applyRiskStyling(p.risk_level);
          verdictText.textContent = p.verdict || verdictText.textContent;
          analysisSummary.textContent = p.analysis_summary || '';
          analysisTimestamp.textContent = (p.generated_at ? `Generated ${new Date(p.generated_at).toLocaleString()}` : analysisTimestamp.textContent);
          if (usageAdvice) usageAdvice.textContent = p.usage_advice || usageAdvice.textContent;
          renderPermissionList(dangerPermList, p.permissions?.dangerous || []);
          renderPermissionList(normalPermList, p.permissions?.normal || []);
          renderDataFlow(dataFlow, p.threat_flow || []);
          renderMitigations(mitigationList, p.actions || []);
          toggleReport(true);
        }
      }
    } catch (_) {}
  };
} catch (_) {
  // SSE may be blocked on some hosts; UI still works via HTTP
}

// IntersectionObserver-based reveal animations
function triggerReveal() {
  const elements = document.querySelectorAll('.anim');
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('in-view');
          observer.unobserve(entry.target);
        }
      });
    },
    { root: null, rootMargin: '0px 0px -10% 0px', threshold: 0.1 }
  );
  elements.forEach((el) => observer.observe(el));
}

triggerReveal();