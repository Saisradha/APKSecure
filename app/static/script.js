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
// Auth elements
const authOverlay = document.getElementById('authOverlay');
const otpRequestForm = document.getElementById('otpRequestForm');
const otpVerifyForm = document.getElementById('otpVerifyForm');
const authEmail = document.getElementById('authEmail');
const authCode = document.getElementById('authCode');
const resendCodeBtn = document.getElementById('resendCode');
const authHelp = document.getElementById('authHelp');
const logoutBtn = document.getElementById('logoutBtn');
// Risk dialog
const riskOverlay = document.getElementById('riskOverlay');
const riskMessage = document.getElementById('riskMessage');
const riskAcknowledge = document.getElementById('riskAcknowledge');
// Alert overlay
const alertOverlay = document.getElementById('alertOverlay');
const alertMessage = document.getElementById('alertMessage');
const alertAcknowledge = document.getElementById('alertAcknowledge');

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
  if (visible) {
    report.style.display = 'grid';
    // Scroll to report smoothly after a brief delay
    setTimeout(() => {
      report.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 300);
  } else {
    report.style.display = 'none';
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

if (analyzerForm) {
  analyzerForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const raw = (packageInput?.value || '').trim();
    if (!raw) {
      showAlert('Please enter a package name or Play Store URL.');
      return;
    }
    
    // Extract package name from URL or use as-is (original logic)
    let pkg = extractPackageName(raw);
    if (!pkg) {
      pkg = raw; // Fallback to raw input
    }
    
    toggleReport(false);
    const analyzeBtn = document.getElementById('analyzeBtn');
    if (analyzeBtn) {
      analyzeBtn.disabled = true;
      analyzeBtn.textContent = 'Analyzing...';
    }

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
      maybeShowRiskDialog(result);

      renderPermissionList(dangerPermList, result.permissions?.dangerous || []);
      renderPermissionList(normalPermList, result.permissions?.normal || []);
      renderDataFlow(dataFlow, result.threat_flow || []);
      renderMitigations(mitigationList, result.actions || []);

      if (visualSummary) {
        visualSummary.textContent = result.visual_summary || visualSummary.textContent;
      }

      toggleReport(true);
      // Hide analyzer section and show report on same page
      if (analyzerSection) analyzerSection.style.display = 'none';
      // Add report to navigation history
      addToHistory('report');
      
      // Re-run animation for newly revealed elements
      requestAnimationFrame(() => {
        document.querySelectorAll('.anim').forEach((el) => el.classList.remove('in-view'));
        triggerReveal();
      });
    } catch (error) {
      toggleReport(false);
      showAlert('Failed to analyze. Please try again.');
      console.error('Analysis error:', error);
    } finally {
      if (analyzeBtn) {
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = 'Analyze App';
      }
    }
  });
}

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
          maybeShowRiskDialog(p);
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

// --- Auth ---
async function checkAuth() {
  try {
    const res = await fetch('/auth/status');
    const data = await res.json();
    const authed = !!data.authenticated;
    authOverlay.setAttribute('aria-hidden', authed ? 'true' : 'false');
    if (logoutBtn) logoutBtn.hidden = !authed;
  } catch (_) {
    // If status check fails, require login by default
    authOverlay.setAttribute('aria-hidden', 'false');
    if (logoutBtn) logoutBtn.hidden = true;
  }
}

checkAuth();

if (otpRequestForm) {
  otpRequestForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = (authEmail.value || '').trim();
    if (!email) return;
    authHelp.textContent = 'Sending code...';
    const res = await fetch('/auth/request-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    const data = await res.json();
    if (data.ok) {
      authHelp.textContent = 'Check your email for the 6-digit code.';
      otpVerifyForm.hidden = false;
      authCode.focus();
    } else {
      authHelp.textContent = data.error || 'Failed to send code.';
    }
  });
}

if (otpVerifyForm) {
  otpVerifyForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = (authEmail.value || '').trim();
    const code = (authCode.value || '').trim();
    if (!email || !code) return;
    authHelp.textContent = 'Verifying...';
    const res = await fetch('/auth/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, code }),
    });
    const data = await res.json();
    if (data.ok) {
      authOverlay.setAttribute('aria-hidden', 'true');
      authHelp.textContent = '';
      if (logoutBtn) logoutBtn.hidden = false;
    } else {
      authHelp.textContent = data.error || 'Invalid code.';
    }
  });
}

if (resendCodeBtn) {
  resendCodeBtn.addEventListener('click', () => {
    otpRequestForm.dispatchEvent(new Event('submit'));
  });
}

if (logoutBtn) {
  logoutBtn.addEventListener('click', async () => {
    try {
      await fetch('/auth/logout', { method: 'POST' });
    } catch (_) {}
    if (logoutBtn) logoutBtn.hidden = true;
    authOverlay.setAttribute('aria-hidden', 'false');
  });
}

// --- Risk dialog helpers ---
function maybeShowRiskDialog(payload) {
  try {
    const level = (payload.risk_level || '').toLowerCase();
    const score = Number(payload.risk_score || 0);
    if (level === 'critical' && score >= 80 && riskOverlay) {
      if (riskMessage) {
        riskMessage.textContent = `High risk for ${payload.app_name || payload.package}: score ${Math.round(score)}/100. We recommend uninstalling and using a trusted alternative.`;
      }
      riskOverlay.setAttribute('aria-hidden', 'false');
    }
  } catch (_) {}
}

if (riskAcknowledge && riskOverlay) {
  const closeRisk = () => riskOverlay.setAttribute('aria-hidden', 'true');
  riskAcknowledge.addEventListener('click', closeRisk);
  riskOverlay.addEventListener('click', (e) => {
    if (e.target === riskOverlay) closeRisk();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeRisk();
  });
}

// --- Alert dialog helpers ---
function showAlert(message) {
  if (!alertOverlay) return;
  if (alertMessage) alertMessage.textContent = message || 'Invalid or wrong URL.';
  alertOverlay.setAttribute('aria-hidden', 'false');
}

if (alertAcknowledge && alertOverlay) {
  const closeAlert = () => alertOverlay.setAttribute('aria-hidden', 'true');
  alertAcknowledge.addEventListener('click', closeAlert);
  alertOverlay.addEventListener('click', (e) => {
    if (e.target === alertOverlay) closeAlert();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeAlert();
  });
}


// ===== Platform Selection =====
const platformSelection = document.getElementById('platformSelection');
const analyzerSection = document.getElementById('analyzerSection');
const websiteSection = document.getElementById('websiteSection');
const playstoreBtn = document.getElementById('playstoreBtn');
const websiteBtn = document.getElementById('websiteBtn');
const websiteForm = document.getElementById('websiteForm');

if (playstoreBtn && analyzerSection) {
  playstoreBtn.addEventListener('click', () => {
    goToSection('analyzerSection');
    navHome?.classList.add('active');
    if (packageInput) packageInput.focus();
  });
}

if (websiteBtn && websiteSection) {
  websiteBtn.addEventListener('click', () => {
    goToSection('websiteSection');
    navWebsite?.classList.add('active');
    navHome?.classList.remove('active');
    const websiteInput = document.getElementById('websiteInput');
    if (websiteInput) websiteInput.focus();
  });
}

if (websiteForm) {
  websiteForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const websiteInput = document.getElementById('websiteInput');
    const analyzeWebsiteBtn = document.getElementById('analyzeWebsiteBtn');
    let url = websiteInput?.value?.trim();
    
    if (!url) {
      showAlert('Please enter a website URL.');
      return;
    }
    
    // Normalize URL - add protocol if missing
    try {
      // If it doesn't start with http:// or https://, add https://
      if (!/^https?:\/\//i.test(url)) {
        url = 'https://' + url;
      }
      // Validate it's a proper URL
      new URL(url);
    } catch (error) {
      showAlert('Please enter a valid website URL (e.g., www.example.com or https://example.com)');
      return;
    }
    
    // Show loading state
    if (analyzeWebsiteBtn) {
      analyzeWebsiteBtn.disabled = true;
      analyzeWebsiteBtn.textContent = 'Analyzing...';
    }
    
    try {
      // For now, show alert (you can implement website analysis later)
      // In the future, you can call an API endpoint for website analysis
      showAlert('Website analysis feature coming soon. For now, you can use PlayStore analysis for mobile apps.');
    } catch (error) {
      showAlert('Failed to analyze website. Please try again.');
      console.error('Website analysis error:', error);
    } finally {
      if (analyzeWebsiteBtn) {
        analyzeWebsiteBtn.disabled = false;
        analyzeWebsiteBtn.textContent = 'Analyze Website';
      }
    }
  });
}

// ===== Navigation =====
const navBack = document.getElementById('navBack');
const navForward = document.getElementById('navForward');
const navHome = document.getElementById('navHome');
const navWebsite = document.getElementById('navWebsite');
const navAbout = document.getElementById('navAbout');
const navContact = document.getElementById('navContact');

// Navigation history
let navHistory = [];
let navHistoryIndex = -1;

function addToHistory(section) {
  navHistory = navHistory.slice(0, navHistoryIndex + 1);
  navHistory.push(section);
  navHistoryIndex = navHistory.length - 1;
  updateNavButtons();
}

function goToSection(sectionId, addToHist = true) {
  // Hide all sections
  if (platformSelection) platformSelection.style.display = 'none';
  if (analyzerSection) analyzerSection.style.display = 'none';
  if (websiteSection) websiteSection.style.display = 'none';
  if (report) report.style.display = 'none';
  const aboutPage = document.getElementById('aboutPage');
  const contactPage = document.getElementById('contactPage');
  if (aboutPage) aboutPage.style.display = 'none';
  if (contactPage) contactPage.style.display = 'none';
  
  // Show selected section
  const section = document.getElementById(sectionId);
  if (section) {
    // Determine display type based on section
    let displayType = 'block';
    if (sectionId === 'analyzerSection' || sectionId === 'websiteSection' || sectionId === 'report' || sectionId === 'aboutPage') {
      displayType = 'grid';
    } else if (sectionId === 'platformSelection' || sectionId === 'contactPage') {
      displayType = 'grid';
    }
    section.style.display = displayType;
    if (addToHist) {
      addToHistory(sectionId);
    } else {
      // Still update buttons even if not adding to history
      updateNavButtons();
    }
    
    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
}

function updateNavButtons() {
  if (navBack) {
    const canGoBack = navHistoryIndex > 0;
    navBack.disabled = !canGoBack;
    navBack.style.opacity = canGoBack ? '1' : '0.4';
    navBack.style.cursor = canGoBack ? 'pointer' : 'not-allowed';
  }
  if (navForward) {
    const canGoForward = navHistoryIndex < navHistory.length - 1;
    navForward.disabled = !canGoForward;
    navForward.style.opacity = canGoForward ? '1' : '0.4';
    navForward.style.cursor = canGoForward ? 'pointer' : 'not-allowed';
  }
}

if (navBack) {
  navBack.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (navHistoryIndex > 0) {
      navHistoryIndex--;
      goToSection(navHistory[navHistoryIndex], false);
      updateNavButtons();
    }
  });
}

if (navForward) {
  navForward.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (navHistoryIndex < navHistory.length - 1) {
      navHistoryIndex++;
      goToSection(navHistory[navHistoryIndex], false);
      updateNavButtons();
    }
  });
}

if (navHome) {
  navHome.addEventListener('click', () => {
    goToSection('platformSelection');
    navHome.classList.add('active');
    navWebsite?.classList.remove('active');
  });
}

if (navWebsite) {
  navWebsite.addEventListener('click', () => {
    if (websiteSection) {
      goToSection('websiteSection');
      navWebsite.classList.add('active');
      navHome?.classList.remove('active');
    }
  });
}

const aboutPage = document.getElementById('aboutPage');
const contactPage = document.getElementById('contactPage');

if (navAbout) {
  navAbout.addEventListener('click', () => {
    goToSection('aboutPage');
    navAbout.classList.add('active');
    navHome?.classList.remove('active');
    navWebsite?.classList.remove('active');
    navContact?.classList.remove('active');
  });
}

if (navContact) {
  navContact.addEventListener('click', () => {
    goToSection('contactPage');
    navContact.classList.add('active');
    navHome?.classList.remove('active');
    navWebsite?.classList.remove('active');
    navAbout?.classList.remove('active');
  });
}

// Contact form submission
const contactForm = document.getElementById('contactForm');
if (contactForm) {
  contactForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const firstName = document.getElementById('firstName')?.value;
    const lastName = document.getElementById('lastName')?.value;
    const email = document.getElementById('contactEmail')?.value;
    const message = document.getElementById('contactMessage')?.value;
    
    if (!firstName || !lastName || !email || !message) {
      showAlert('Please fill in all fields.');
      return;
    }
    
    // Here you would send the form data to your backend
    // For now, we'll show a success message
    showAlert('Thank you for contacting us! We will respond within 24 hours.');
    contactForm.reset();
  });
}

// Initialize navigation on page load
function initializeNavigation() {
  if (platformSelection) {
    // Reset history and add initial section
    navHistory = ['platformSelection'];
    navHistoryIndex = 0;
    updateNavButtons();
  }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeNavigation);
} else {
  initializeNavigation();
}