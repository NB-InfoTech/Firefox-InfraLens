const FEATURE_DEFAULTS = {
  siteInfo: true,
  infrastructureProfile: true,
  securityScore: true,
  securityHeaders: true,
  cookies: true,
  mixedContent: true,
  redirectChain: true,
  blocklistCheck: true,
  copyCurl: true,
  reloadTab: true,
  hardReloadTab: true,
  exportTxt: true,
  exportJson: true,
  securityHeadersTool: true,
  sslLabsTool: true,
  virusTotalTool: true,
  sucuriTool: true
};

const FEATURE_LABELS = {
  siteInfo: "Site, protocol, and load time",
  infrastructureProfile: "IP, CDN, CMS, TLS, language, and analytics",
  securityScore: "Security score",
  securityHeaders: "Security headers",
  cookies: "Cookie security summary",
  mixedContent: "Mixed content",
  redirectChain: "Redirect chain",
  blocklistCheck: "Blocklist check section",
  copyCurl: "Copy curl",
  reloadTab: "Reload tab",
  hardReloadTab: "Hard reload",
  exportTxt: "Export TXT",
  exportJson: "Export JSON",
  securityHeadersTool: "SecurityHeaders tool",
  sslLabsTool: "SSL Labs tool",
  virusTotalTool: "VirusTotal tool",
  sucuriTool: "Sucuri SiteCheck tool"
};

function getFeatureSettings(callback) {
  chrome.storage.sync.get({ featureSettings: FEATURE_DEFAULTS }, (result) => {
    callback({
      ...FEATURE_DEFAULTS,
      ...(result.featureSettings || {})
    });
  });
}

function saveFeatureSettings(settings, callback) {
  chrome.storage.sync.set({ featureSettings: settings }, callback);
}
