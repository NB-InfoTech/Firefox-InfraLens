document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("version").textContent = `v${chrome.runtime.getManifest().version}`;

  document.getElementById("openSettings").onclick = () => {
    chrome.tabs.create({ url: chrome.runtime.getURL("settings.html") });
  };

  getFeatureSettings((featureSettings) => {
    applyFeatureVisibility(featureSettings);

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs || !tabs[0] || !tabs[0].url) return;

      const tab = tabs[0];
      const pageUrl = new URL(tab.url);
      const isWebPage = pageUrl.protocol === "http:" || pageUrl.protocol === "https:";

      document.getElementById("site").textContent = pageUrl.hostname || pageUrl.href;

      setStatus(
        "protocol",
        pageUrl.protocol === "https:" ? "HTTPS" : pageUrl.protocol.replace(":", "").toUpperCase(),
        pageUrl.protocol === "https:" ? "ok" : "bad"
      );

      if (!isWebPage) {
        setLoadTime(null);
        renderUnsupportedPage();
        return;
      }

      chrome.runtime.sendMessage({ type: "GET_PAGE_SECURITY", tabId: tab.id }, (cachedData) => {
        if (!canActiveScan(pageUrl)) {
          const audit = buildAudit(pageUrl, cachedData || {});
          setLoadTime(audit.responseTimeMs);
          renderAudit(audit);
          bindActions(audit, tab.id);
          return;
        }

        chrome.runtime.sendMessage({ type: "SCAN_URL", url: pageUrl.href }, (activeData) => {
          const audit = buildAudit(pageUrl, mergeScanData(cachedData || {}, activeData || {}));
          if (activeData && activeData.ok && activeData.finalUrl && activeData.finalUrl !== pageUrl.href) {
            audit.finalUrl = activeData.finalUrl;
          }

          setLoadTime(audit.responseTimeMs);
          renderAudit(audit);
          bindActions(audit, tab.id);
        });
      });
    });
  });
});

function applyFeatureVisibility(featureSettings) {
  document.querySelectorAll("[data-feature]").forEach((el) => {
    const feature = el.dataset.feature;
    el.hidden = featureSettings[feature] === false;
  });
}

function canActiveScan(pageUrl) {
  const blockedHosts = new Set([
    "chrome.google.com",
    "chromewebstore.google.com",
    "microsoftedge.microsoft.com",
    "addons.mozilla.org"
  ]);

  return !blockedHosts.has(pageUrl.hostname);
}

function mergeScanData(cachedData, activeData) {
  if (!activeData || !activeData.ok) {
    return cachedData;
  }

  return {
    ...cachedData,
    headers: {
      ...(cachedData.headers || {}),
      ...(activeData.headers || {})
    },
    responseTimeMs: activeData.responseTimeMs || cachedData.responseTimeMs || null,
    redirects:
      activeData.redirects && activeData.redirects.length
        ? activeData.redirects
        : cachedData.redirects || [],
    infrastructure: activeData.infrastructure || cachedData.infrastructure || null,
    activeScan: {
      statusCode: activeData.statusCode || null,
      finalUrl: activeData.finalUrl || null
    }
  };
}

function setStatus(id, text, className) {
  const el = document.getElementById(id);
  el.textContent = text;
  el.className = `value ${className}`;
}

function setLoadTime(responseTimeMs) {
  const loadTimeEl = document.getElementById("loadTime");

  loadTimeEl.textContent = responseTimeMs ? `${responseTimeMs} ms` : "Unavailable";
  loadTimeEl.className = "value muted";
}

function buildAudit(pageUrl, data) {
  const headers = data.headers || {};
  const cookies = data.cookies || [];
  const mixedActive = data.mixedActive || 0;
  const mixedPassive = data.mixedPassive || 0;
  const redirects = data.redirects || [];
  const findings = [];
  let score = 100;

  function penalize(condition, points, message) {
    if (condition) {
      score -= points;
      findings.push(message);
    }
  }

  const cspValue = headers["content-security-policy"] || "";
  const cspWarnings = analyzeCsp(cspValue);
  const seriousCspWarnings = cspWarnings.filter((warning) => warning !== "missing default-src");
  const cookieSummary = analyzeCookies(cookies);

  penalize(pageUrl.protocol !== "https:", 30, "Page is not served over HTTPS.");
  penalize(!headers["strict-transport-security"], 15, "HSTS is missing.");
  penalize(!cspValue, 15, "Content Security Policy is missing.");
  penalize(seriousCspWarnings.length > 0, 10, "Content Security Policy contains weak directives.");
  penalize(!headers["x-frame-options"], 8, "X-Frame-Options is missing.");
  penalize(!headers["x-content-type-options"], 8, "X-Content-Type-Options is missing.");
  penalize(!headers["referrer-policy"], 5, "Referrer-Policy is missing.");
  penalize(!headers["permissions-policy"], 5, "Permissions-Policy is missing.");
  penalize(mixedActive > 0, 20, "Active mixed content was detected.");
  penalize(mixedActive === 0 && mixedPassive > 0, 8, "Passive mixed content was detected.");
  penalize(redirects.some((r) => r.to && r.to.startsWith("http:")), 12, "Redirect chain includes insecure HTTP.");

  if (cookieSummary.insecure > 0) findings.push("Some cookies are missing Secure.");
  if (cookieSummary.noHttpOnly > 0) findings.push("Some cookies are missing HttpOnly.");
  if (cookieSummary.noSameSite > 0) findings.push("Some cookies are missing SameSite.");
  if (cspWarnings.includes("missing default-src")) {
    findings.push("Content Security Policy is present but does not define default-src.");
  }

  score = Math.max(0, score);

  return {
    site: pageUrl.hostname,
    url: pageUrl.href,
    protocol: pageUrl.protocol === "https:" ? "HTTPS" : "HTTP",
    infrastructure: normalizeInfrastructure(data.infrastructure),
    score,
    grade: gradeScore(score),
    responseTimeMs: data.responseTimeMs || null,
    headers,
    cspWarnings,
    cookies,
    cookieSummary,
    mixed_content: {
      active: mixedActive,
      passive: mixedPassive
    },
    redirect_chain: redirects,
    findings,
    generated_at: new Date().toISOString()
  };
}

function analyzeCsp(cspValue) {
  if (!cspValue) return [];

  const warnings = [];
  const normalized = cspValue.toLowerCase();

  if (normalized.includes("'unsafe-inline'") || normalized.includes("unsafe-inline")) {
    warnings.push("unsafe-inline");
  }

  if (normalized.includes("'unsafe-eval'") || normalized.includes("unsafe-eval")) {
    warnings.push("unsafe-eval");
  }

  if (normalized.includes("*")) {
    warnings.push("wildcard source");
  }

  if (!normalized.includes("default-src")) {
    warnings.push("missing default-src");
  }

  return warnings;
}

function analyzeCookies(cookies) {
  return cookies.reduce(
    (summary, cookie) => {
      if (!cookie.secure) summary.insecure++;
      if (!cookie.httpOnly) summary.noHttpOnly++;
      if (!cookie.sameSite) summary.noSameSite++;
      summary.total++;
      return summary;
    },
    { total: 0, insecure: 0, noHttpOnly: 0, noSameSite: 0 }
  );
}

function gradeScore(score) {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

function renderAudit(audit) {
  const scoreEl = document.getElementById("score");
  scoreEl.textContent = `${audit.grade} ${audit.score}`;
  scoreEl.className = audit.score >= 80 ? "ok" : audit.score >= 60 ? "warn" : "bad";

  renderHeader("hsts", audit.headers["strict-transport-security"], "Present", "Missing");
  renderHeader("xfo", audit.headers["x-frame-options"], "Present", "Missing");
  renderHeader("xcto", audit.headers["x-content-type-options"], "Present", "Missing");
  renderHeader("referrerPolicy", audit.headers["referrer-policy"], "Present", "Missing");
  renderHeader("permissionsPolicy", audit.headers["permissions-policy"], "Present", "Missing");

  const cspEl = document.getElementById("csp");
  if (!audit.headers["content-security-policy"]) {
    cspEl.textContent = "Missing";
    cspEl.className = "value bad";
  } else if (audit.cspWarnings.some((warning) => warning !== "missing default-src")) {
    cspEl.textContent = "Present, weak";
    cspEl.className = "value warn";
  } else {
    cspEl.textContent = "Present";
    cspEl.className = "value ok";
  }

  renderCookies(audit.cookieSummary);
  renderInfrastructure(audit.infrastructure);
  renderMixedContent(audit.mixed_content);
  renderRedirects(audit.redirect_chain);
  renderBlocklistCheck(audit);
}

function normalizeInfrastructure(infrastructure) {
  return {
    ipAddresses: infrastructure && infrastructure.ipAddresses ? infrastructure.ipAddresses : [],
    canonicalName: infrastructure && infrastructure.canonicalName ? infrastructure.canonicalName : "",
    cdn: infrastructure && infrastructure.cdn ? infrastructure.cdn : "Unknown",
    language: infrastructure && infrastructure.language ? infrastructure.language : "Unknown",
    tlsCertificate: infrastructure && infrastructure.tlsCertificate ? infrastructure.tlsCertificate : "Unavailable",
    cms: infrastructure && infrastructure.cms ? infrastructure.cms : "Unknown",
    appVersion: infrastructure && infrastructure.appVersion ? infrastructure.appVersion : "Unknown",
    appTheme: infrastructure && infrastructure.appTheme ? infrastructure.appTheme : "Unknown",
    appDirectory: infrastructure && infrastructure.appDirectory ? infrastructure.appDirectory : "Unknown",
    analytics: infrastructure && infrastructure.analytics ? infrastructure.analytics : "Unknown"
  };
}

function renderInfrastructure(infrastructure) {
  const ipAddresses = infrastructure.ipAddresses || [];
  const ipAddressEl = document.getElementById("ipAddress");
  const cdnProviderEl = document.getElementById("cdnProvider");
  const languageInfoEl = document.getElementById("languageInfo");
  const tlsCertificateEl = document.getElementById("tlsCertificate");
  const cmsProviderEl = document.getElementById("cmsProvider");
  const appVersionEl = document.getElementById("appVersion");
  const appThemeEl = document.getElementById("appTheme");
  const appDirectoryEl = document.getElementById("appDirectory");
  const analyticsInfoEl = document.getElementById("analyticsInfo");

  ipAddressEl.textContent = ipAddresses.length ? ipAddresses.slice(0, 3).join(", ") : "Unavailable";
  ipAddressEl.title = ipAddresses.join(", ");
  ipAddressEl.className = `value ${ipAddresses.length ? "ok" : "muted"}`;

  cdnProviderEl.textContent = infrastructure.cdn || "Unknown";
  cdnProviderEl.className = `value ${infrastructure.cdn && infrastructure.cdn !== "Unknown" ? "ok" : "muted"}`;

  languageInfoEl.textContent = infrastructure.language || "Unknown";
  languageInfoEl.className = `value ${infrastructure.language && infrastructure.language !== "Unknown" ? "ok" : "muted"}`;

  tlsCertificateEl.textContent = infrastructure.tlsCertificate || "Unavailable";
  tlsCertificateEl.className = `value ${infrastructure.tlsCertificate && infrastructure.tlsCertificate !== "Unavailable" ? "ok" : "muted"}`;

  cmsProviderEl.textContent = infrastructure.cms || "Unknown";
  cmsProviderEl.className = `value ${infrastructure.cms && infrastructure.cms !== "Unknown" ? "ok" : "muted"}`;

  appVersionEl.textContent = infrastructure.appVersion || "Unknown";
  appVersionEl.className = `value ${infrastructure.appVersion && infrastructure.appVersion !== "Unknown" ? "ok" : "muted"}`;

  appThemeEl.textContent = infrastructure.appTheme || "Unknown";
  appThemeEl.title = infrastructure.appTheme || "";
  appThemeEl.className = `value ${infrastructure.appTheme && infrastructure.appTheme !== "Unknown" ? "ok" : "muted"}`;

  appDirectoryEl.textContent = infrastructure.appDirectory || "Unknown";
  appDirectoryEl.title = infrastructure.appDirectory || "";
  appDirectoryEl.className = `value ${infrastructure.appDirectory && infrastructure.appDirectory !== "Unknown" ? "ok" : "muted"}`;

  analyticsInfoEl.textContent = infrastructure.analytics || "Unknown";
  analyticsInfoEl.title = infrastructure.analytics || "";
  analyticsInfoEl.className = `value ${infrastructure.analytics && infrastructure.analytics !== "Unknown" ? "ok" : "muted"}`;
}

function renderHeader(id, value, okText, missingText) {
  const el = document.getElementById(id);
  el.textContent = value ? okText : missingText;
  el.className = `value ${value ? "ok" : "warn"}`;
}

function renderCookies(summary) {
  const cookiesEl = document.getElementById("cookies");

  if (summary.total === 0) {
    cookiesEl.textContent = "No Set-Cookie headers detected on page response.";
    cookiesEl.className = "mono muted";
    return;
  }

  const lines = [
    `Total: ${summary.total}`,
    `Missing Secure: ${summary.insecure}`,
    `Missing HttpOnly: ${summary.noHttpOnly}`,
    `Missing SameSite: ${summary.noSameSite}`
  ];

  cookiesEl.textContent = lines.join("\n");
  cookiesEl.className =
    summary.insecure || summary.noHttpOnly || summary.noSameSite ? "mono warn" : "mono ok";
}

function renderMixedContent(mixedContent) {
  const mixedEl = document.getElementById("mixedContent");
  const active = mixedContent.active;
  const passive = mixedContent.passive;

  if (active === 0 && passive === 0) {
    mixedEl.textContent = "No mixed content detected";
    mixedEl.className = "ok";
  } else if (active > 0) {
    mixedEl.textContent = `Active mixed content detected (${active} requests)`;
    mixedEl.className = "bad";
  } else {
    mixedEl.textContent = `Passive mixed content detected (${passive} requests)`;
    mixedEl.className = "warn";
  }
}

function renderRedirects(redirects) {
  const redirectsEl = document.getElementById("redirects");

  if (!redirects || redirects.length === 0) {
    redirectsEl.textContent = "No redirects detected";
    redirectsEl.className = "mono ok";
    return;
  }

  redirectsEl.textContent = redirects
    .map((r, i) => `${i + 1}. ${r.from} -> ${r.to} (${r.statusCode})`)
    .join("\n");
  redirectsEl.className = redirects.some((r) => r.to && r.to.startsWith("http:"))
    ? "mono warn"
    : "mono ok";
}

function renderBlocklistCheck(audit) {
  const sucuriStatusEl = document.getElementById("sucuriStatus");
  sucuriStatusEl.textContent = "Manual check";
  sucuriStatusEl.className = "value muted";
}

function renderUnsupportedPage() {
  ["hsts", "csp", "xfo", "xcto", "referrerPolicy", "permissionsPolicy"].forEach((id) => {
    setStatus(id, "Unsupported page", "muted");
  });

  document.getElementById("score").textContent = "--";
  document.getElementById("ipAddress").textContent = "Unsupported page";
  document.getElementById("cdnProvider").textContent = "Unsupported page";
  document.getElementById("languageInfo").textContent = "Unsupported page";
  document.getElementById("tlsCertificate").textContent = "Unsupported page";
  document.getElementById("cmsProvider").textContent = "Unsupported page";
  document.getElementById("appVersion").textContent = "Unsupported page";
  document.getElementById("appTheme").textContent = "Unsupported page";
  document.getElementById("appDirectory").textContent = "Unsupported page";
  document.getElementById("analyticsInfo").textContent = "Unsupported page";
  document.getElementById("cookies").textContent = "Only HTTP and HTTPS pages can be inspected.";
  document.getElementById("mixedContent").textContent = "Unsupported page";
  document.getElementById("redirects").textContent = "Unsupported page";
}

function bindActions(audit, tabId) {
  document.getElementById("copyCurl").onclick = async () => {
    const command = `curl -I ${quoteForShell(audit.url)}`;
    await navigator.clipboard.writeText(command);
  };

  document.getElementById("reloadTab").onclick = () => {
    chrome.tabs.reload(tabId);
  };

  document.getElementById("hardReloadTab").onclick = () => {
    chrome.tabs.reload(tabId, { bypassCache: true });
  };

  document.getElementById("exportTxt").onclick = () => {
    downloadFile("infralens_audit.txt", buildTxtReport(audit), "text/plain");
  };

  document.getElementById("exportJson").onclick = () => {
    downloadFile("infralens_audit.json", JSON.stringify(audit, null, 2), "application/json");
  };

  document.getElementById("openSecurityHeaders").onclick = () => {
    chrome.tabs.create({ url: `https://securityheaders.com/?q=${encodeURIComponent(audit.url)}` });
  };

  document.getElementById("openSslLabs").onclick = () => {
    chrome.tabs.create({ url: `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(audit.site)}` });
  };

  document.getElementById("openVirusTotal").onclick = () => {
    chrome.tabs.create({ url: buildVirusTotalUrl(audit.site) });
  };

  document.getElementById("openSucuri").onclick = () => {
    chrome.tabs.create({ url: buildSucuriSiteCheckUrl(audit.url) });
  };
}

function buildVirusTotalUrl(hostname) {
  const normalizedHost = hostname.replace(/^\[|\]$/g, "");
  const route = isIpAddress(normalizedHost) ? "ip-address" : "domain";
  return `https://www.virustotal.com/gui/${route}/${encodeURIComponent(normalizedHost)}`;
}

function isIpAddress(value) {
  const ipv4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  const ipv6 = /^[0-9a-f:]+$/i;
  return ipv4.test(value) || (value.includes(":") && ipv6.test(value));
}

function buildSucuriSiteCheckUrl(targetUrl) {
  const url = new URL(targetUrl);
  const protocol = url.protocol.replace(":", "");
  const path = url.pathname === "/" ? "" : url.pathname.replace(/^\/+/, "");
  const query = url.search ? url.search.replace(/^\?/, "") : "";
  const suffix = [path, query].filter(Boolean).join("?");
  const target = [protocol, url.hostname, suffix].filter(Boolean).join("/");

  return `https://sitecheck.sucuri.net/results/${target}`;
}

function buildTxtReport(audit) {
  const headerLines = Object.entries(audit.headers)
    .map(([name, value]) => `  ${name}: ${value || "Missing"}`)
    .join("\n");

  const redirectLines = audit.redirect_chain.length
    ? audit.redirect_chain
        .map((r, i) => `  ${i + 1}. ${r.from} -> ${r.to} (${r.statusCode})`)
        .join("\n")
    : "  None";

  const findingLines = audit.findings.length
    ? audit.findings.map((finding) => `  - ${finding}`).join("\n")
    : "  None";

  return [
    "InfraLens Security Audit Report",
    "",
    `Site: ${audit.site}`,
    `URL: ${audit.url}`,
    `Protocol: ${audit.protocol}`,
    `Score: ${audit.grade} ${audit.score}`,
    "",
    "External Checks:",
    `  Sucuri SiteCheck: ${buildSucuriSiteCheckUrl(audit.url)}`,
    `  SecurityHeaders: https://securityheaders.com/?q=${encodeURIComponent(audit.url)}`,
    `  SSL Labs: https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(audit.site)}`,
    `  VirusTotal: ${buildVirusTotalUrl(audit.site)}`,
    "",
    "Infrastructure:",
    `  IP Address: ${audit.infrastructure.ipAddresses.length ? audit.infrastructure.ipAddresses.join(", ") : "Unavailable"}`,
    `  Canonical Name: ${audit.infrastructure.canonicalName || "Unavailable"}`,
    `  CDN: ${audit.infrastructure.cdn || "Unknown"}`,
    `  Language: ${audit.infrastructure.language || "Unknown"}`,
    `  TLS Certificate: ${audit.infrastructure.tlsCertificate || "Unavailable"}`,
    `  CMS: ${audit.infrastructure.cms || "Unknown"}`,
    `  Version: ${audit.infrastructure.appVersion || "Unknown"}`,
    `  Theme: ${audit.infrastructure.appTheme || "Unknown"}`,
    `  Directory: ${audit.infrastructure.appDirectory || "Unknown"}`,
    `  Ads/analytics: ${audit.infrastructure.analytics || "Unknown"}`,
    "",
    "Security Headers:",
    headerLines,
    "",
    "Cookies:",
    `  Total: ${audit.cookieSummary.total}`,
    `  Missing Secure: ${audit.cookieSummary.insecure}`,
    `  Missing HttpOnly: ${audit.cookieSummary.noHttpOnly}`,
    `  Missing SameSite: ${audit.cookieSummary.noSameSite}`,
    "",
    "Mixed Content:",
    `  Active: ${audit.mixed_content.active}`,
    `  Passive: ${audit.mixed_content.passive}`,
    "",
    "Redirect Chain:",
    redirectLines,
    "",
    "Findings:",
    findingLines,
    "",
    `Generated at: ${audit.generated_at}`
  ].join("\n");
}

function downloadFile(filename, content, type) {
  const blob = new Blob([content], { type });
  const blobUrl = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = blobUrl;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(blobUrl);
}

function quoteForShell(value) {
  return `"${value.replace(/"/g, '\\"')}"`;
}
