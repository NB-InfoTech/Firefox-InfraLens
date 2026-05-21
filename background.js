const cache = {};

const HEADER_NAMES = [
  "strict-transport-security",
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy"
];

const INFRA_HEADER_NAMES = [
  "server",
  "x-powered-by",
  "x-generator",
  "link",
  "x-cache",
  "x-served-by",
  "x-cdn",
  "x-vercel-id",
  "x-nf-request-id",
  "cf-cache-status",
  "cf-ray",
  "x-amz-cf-id",
  "x-amz-cf-pop",
  "x-sucuri-id",
  "x-sucuri-cache",
  "x-drupal-cache",
  "x-pantheon-styx-hostname"
];

const ACTIVE_MIXED_TYPES = new Set([
  "script",
  "xmlhttprequest",
  "sub_frame",
  "stylesheet",
  "object",
  "ping"
]);

const RESPONSE_HEADER_OPTIONS =
  typeof browser === "undefined" ? ["responseHeaders", "extraHeaders"] : ["responseHeaders"];

function defaultEntry() {
  return {
    headers: {},
    cookies: [],
    mixedActive: 0,
    mixedPassive: 0,
    redirects: [],
    requestStartedAt: null,
    responseTimeMs: null,
    mainFrameUrl: null,
    mainRequestId: null,
    infrastructure: defaultInfrastructure()
  };
}

function defaultInfrastructure() {
  return {
    ipAddresses: [],
    canonicalName: "",
    cdn: "Unknown",
    language: "Unknown",
    tlsCertificate: "Unavailable",
    cms: "Unknown",
    appVersion: "Unknown",
    appTheme: "Unknown",
    appDirectory: "Unknown",
    analytics: "Unknown"
  };
}

function entryFor(tabId) {
  cache[tabId] = cache[tabId] || defaultEntry();
  return cache[tabId];
}

function normalizeHeaders(responseHeaders) {
  const headers = {};

  for (const header of responseHeaders || []) {
    const name = header.name.toLowerCase();

    if (HEADER_NAMES.includes(name)) {
      headers[name] = header.value || "";
    }
  }

  return headers;
}

function parseSetCookieHeaders(responseHeaders) {
  return (responseHeaders || [])
    .filter((header) => header.name.toLowerCase() === "set-cookie")
    .map((header) => {
      const value = header.value || "";
      const parts = value.split(";").map((part) => part.trim());
      const [nameValue] = parts;
      const name = nameValue.split("=")[0] || "unknown";
      const attributes = parts.slice(1).map((part) => part.toLowerCase());

      return {
        name,
        secure: attributes.includes("secure"),
        httpOnly: attributes.includes("httponly"),
        sameSite: attributes.some((part) => part.startsWith("samesite="))
      };
    });
}

function headersToObject(headers) {
  const result = {};

  for (const [name, value] of headers.entries()) {
    const lowerName = name.toLowerCase();
    if (HEADER_NAMES.includes(lowerName)) {
      result[lowerName] = value || "";
    }
  }

  return result;
}

function infrastructureHeadersToObject(headers) {
  const result = {};

  for (const [name, value] of headers.entries()) {
    const lowerName = name.toLowerCase();
    if (INFRA_HEADER_NAMES.includes(lowerName)) {
      result[lowerName] = value || "";
    }
  }

  return result;
}

async function resolveHostname(hostname) {
  const dnsApi = typeof browser !== "undefined" && browser.dns ? browser.dns : null;

  if (!dnsApi || !hostname || isIpAddress(hostname)) {
    return {
      ipAddresses: isIpAddress(hostname) ? [hostname] : [],
      canonicalName: ""
    };
  }

  try {
    const record = await dnsApi.resolve(hostname, ["canonical_name"]);
    return {
      ipAddresses: record.addresses || [],
      canonicalName: record.canonicalName || ""
    };
  } catch (error) {
    return {
      ipAddresses: [],
      canonicalName: ""
    };
  }
}

async function readHtmlSample(response) {
  const contentType = response.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("text/html")) return "";

  try {
    const text = await response.text();
    return text.slice(0, 250000);
  } catch (error) {
    return "";
  }
}

function detectCdn(headers, canonicalName) {
  const evidence = `${Object.entries(headers)
    .map(([name, value]) => `${name}: ${value}`)
    .join("\n")}\n${canonicalName}`.toLowerCase();

  const signatures = [
    ["Cloudflare", ["cf-ray", "cf-cache-status", "cloudflare"]],
    ["Akamai", ["akamai", "edgesuite", "edgekey"]],
    ["Amazon CloudFront", ["cloudfront", "x-amz-cf-id", "x-amz-cf-pop"]],
    ["Fastly", ["fastly", "x-served-by"]],
    ["Vercel Edge Network", ["vercel", "x-vercel-id"]],
    ["Netlify Edge", ["netlify", "x-nf-request-id"]],
    ["Sucuri", ["sucuri", "x-sucuri-id", "x-sucuri-cache"]],
    ["Bunny CDN", ["bunnycdn", "bunny.net"]],
    ["CDN77", ["cdn77"]],
    ["Imperva", ["imperva", "incapsula"]],
    ["Google Cloud CDN", ["google", "gstatic"]],
    ["Microsoft Azure CDN", ["azureedge", "trafficmanager"]]
  ];

  const match = signatures.find(([, tokens]) => tokens.some((token) => evidence.includes(token)));
  return match ? match[0] : "Unknown";
}

function detectCms(headers, html) {
  const evidence = `${Object.entries(headers)
    .map(([name, value]) => `${name}: ${value}`)
    .join("\n")}\n${html}`.toLowerCase();

  const signatures = [
    ["WordPress", ["wp-content", "wp-includes", "wp-json", "generator\" content=\"wordpress"]],
    ["Drupal", ["drupal", "x-drupal-cache", "sites/default/files"]],
    ["Joomla", ["joomla", "com_content", "/media/system/js/"]],
    ["Shopify", ["cdn.shopify.com", "x-shopify", "shopify-digital-wallet"]],
    ["Wix", ["wix.com", "x-wix", "wixstatic.com"]],
    ["Squarespace", ["squarespace", "static1.squarespace.com"]],
    ["Webflow", ["webflow", "wf-page"]],
    ["Ghost", ["ghost", "ghost.org", "ghost/content"]],
    ["Magento", ["magento", "mage/cookies"]],
    ["Blogger", ["blogger", "blogspot"]]
  ];

  const match = signatures.find(([, tokens]) => tokens.some((token) => evidence.includes(token)));
  return match ? match[0] : "Unknown";
}

function detectLanguage(headers, html) {
  const poweredBy = headers["x-powered-by"] || "";
  const server = headers.server || "";
  const generator = headers["x-generator"] || "";
  const evidence = `${poweredBy}\n${server}\n${generator}\n${html}`;

  const phpMatch = evidence.match(/php\/?\s*([0-9]+(?:\.[0-9]+){0,2})?/i);
  if (phpMatch) return phpMatch[1] ? `PHP ${phpMatch[1]}` : "PHP";

  const aspMatch = evidence.match(/asp\.net(?:\s*version)?\/?\s*([0-9]+(?:\.[0-9]+){0,2})?/i);
  if (aspMatch) return aspMatch[1] ? `ASP.NET ${aspMatch[1]}` : "ASP.NET";

  const expressMatch = evidence.match(/express/i);
  if (expressMatch) return "Node.js / Express";

  const nextMatch = evidence.match(/next\.js|__next/i);
  if (nextMatch) return "Node.js / Next.js";

  const railsMatch = evidence.match(/phusion passenger|ruby on rails|rails/i);
  if (railsMatch) return "Ruby on Rails";

  return "Unknown";
}

function detectAppVersion(cms, headers, html) {
  const generator = headers["x-generator"] || "";
  const evidence = `${generator}\n${html}`;

  if (cms === "WordPress") {
    const match = evidence.match(/wordpress\s*([0-9]+(?:\.[0-9]+){0,2})/i);
    return match ? match[1] : "Unknown";
  }

  if (cms === "Drupal") {
    const match = evidence.match(/drupal\s*([0-9]+(?:\.[0-9]+){0,2})/i);
    return match ? match[1] : "Unknown";
  }

  if (cms === "Joomla") {
    const match = evidence.match(/joomla!?\s*([0-9]+(?:\.[0-9]+){0,2})/i);
    return match ? match[1] : "Unknown";
  }

  const genericMatch = evidence.match(/generator["'][^>]*content=["']([^"']+)["']/i);
  return genericMatch ? genericMatch[1].trim() : "Unknown";
}

function detectTheme(pageUrl, cms, html) {
  if (cms !== "WordPress") return "Unknown";

  const match = html.match(/https?:\/\/[^"'\s<>]+\/wp-content\/themes\/[^"'\s<>/]+\/?/i);
  if (match) return match[0];

  const relativeMatch = html.match(/\/wp-content\/themes\/([^"'\s<>/]+)\//i);
  if (relativeMatch) {
    return `${pageUrl.origin}/wp-content/themes/${relativeMatch[1]}/`;
  }

  return "Unknown";
}

function detectDirectory(pageUrl, cms, html) {
  if (cms === "WordPress" && html.includes("/wp-content/")) {
    return `${pageUrl.origin}/wp-content/`;
  }

  if (cms === "Drupal" && html.includes("/sites/default/")) {
    return `${pageUrl.origin}/sites/default/`;
  }

  if (cms === "Joomla" && html.includes("/media/system/")) {
    return `${pageUrl.origin}/media/system/`;
  }

  return "Unknown";
}

function detectAnalytics(html) {
  const results = [];
  const patterns = [
    ["Google Analytics", /\bUA-\d{4,}-\d+\b/g],
    ["Google Analytics 4", /\bG-[A-Z0-9]{6,}\b/g],
    ["Google Tag Manager", /\bGTM-[A-Z0-9]+\b/g],
    ["Meta Pixel", /fbq\(|connect\.facebook\.net\/signals\/config\/(\d+)/i],
    ["Microsoft Clarity", /clarity\.ms\/tag\/([a-z0-9]+)/i],
    ["Hotjar", /static\.hotjar\.com|hjid['"]?\s*[:=]\s*(\d+)/i]
  ];

  for (const [name, pattern] of patterns) {
    if (pattern.global) {
      const matches = [...html.matchAll(pattern)].map((match) => match[0]);
      if (matches.length) {
        results.push(`${name}: ${[...new Set(matches)].slice(0, 3).join(", ")}`);
      }
    } else {
      const match = html.match(pattern);
      if (match) {
        results.push(match[1] ? `${name}: ${match[1]}` : name);
      }
    }
  }

  return results.length ? results.join("; ") : "Unknown";
}

function commonNameFromDistinguishedName(value) {
  if (!value) return "";
  const match = value.match(/(?:^|,)CN=([^,]+)/);
  return match ? match[1].trim() : value;
}

async function getTlsCertificateInfo(requestId) {
  if (typeof browser === "undefined" || !browser.webRequest || !browser.webRequest.getSecurityInfo) {
    return "Unavailable";
  }

  try {
    const securityInfo = await browser.webRequest.getSecurityInfo(requestId, { certificateChain: false });
    const certificate = securityInfo.certificates && securityInfo.certificates[0];
    if (!certificate || !certificate.issuer) return "Unavailable";

    return `Issued by ${commonNameFromDistinguishedName(certificate.issuer)}`;
  } catch (error) {
    return "Unavailable";
  }
}

async function inspectInfrastructure(url, response) {
  const pageUrl = new URL(response.url || url);
  const dnsResult = await resolveHostname(pageUrl.hostname);
  const infraHeaders = infrastructureHeadersToObject(response.headers);
  const htmlSample = await readHtmlSample(response);
  const cms = detectCms(infraHeaders, htmlSample);

  return {
    ...dnsResult,
    cdn: detectCdn(infraHeaders, dnsResult.canonicalName),
    language: detectLanguage(infraHeaders, htmlSample),
    cms,
    appVersion: detectAppVersion(cms, infraHeaders, htmlSample),
    appTheme: detectTheme(pageUrl, cms, htmlSample),
    appDirectory: detectDirectory(pageUrl, cms, htmlSample),
    analytics: detectAnalytics(htmlSample)
  };
}

function isIpAddress(value) {
  const ipv4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  const ipv6 = /^[0-9a-f:]+$/i;
  return ipv4.test(value) || (value.includes(":") && ipv6.test(value));
}

async function scanUrl(url) {
  const startedAt = Date.now();
  const { response, redirects } = await fetchWithRedirects(url);
  const responseTimeMs = Date.now() - startedAt;

  return {
    headers: headersToObject(response.headers),
    infrastructure: await inspectInfrastructure(url, response.clone()),
    statusCode: response.status,
    finalUrl: response.url,
    redirects,
    responseTimeMs
  };
}

function isRedirectStatus(statusCode) {
  return statusCode >= 300 && statusCode < 400;
}

function resolveRedirectUrl(fromUrl, location) {
  try {
    return new URL(location, fromUrl).href;
  } catch (error) {
    return "";
  }
}

async function fetchWithRedirects(url) {
  const redirects = [];
  let currentUrl = url;
  let response = null;

  for (let i = 0; i < 10; i++) {
    response = await fetch(currentUrl, {
      cache: "no-store",
      credentials: "omit",
      method: "GET",
      redirect: "manual"
    });

    const location = response.headers.get("location");
    if (!isRedirectStatus(response.status) || !location) break;

    const nextUrl = resolveRedirectUrl(currentUrl, location);
    redirects.push({
      from: currentUrl,
      to: nextUrl || location,
      statusCode: response.status
    });

    if (!nextUrl || redirects.some((redirect) => redirect.from === nextUrl)) break;
    currentUrl = nextUrl;
  }

  if (!response || isRedirectStatus(response.status)) {
    response = await fetch(currentUrl, {
      cache: "no-store",
      credentials: "omit",
      method: "GET",
      redirect: "follow"
    });
  }

  return { response, redirects };
}

// Reset page-level state as soon as the top-level navigation starts.
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0) return;

    if (details.type === "main_frame") {
      const existingEntry = cache[details.tabId];
      if (existingEntry && existingEntry.mainRequestId === details.requestId) {
        existingEntry.mainFrameUrl = details.url;
        return;
      }

      cache[details.tabId] = {
        ...defaultEntry(),
        requestStartedAt: details.timeStamp,
        mainFrameUrl: details.url,
        mainRequestId: details.requestId
      };
      return;
    }

    const entry = cache[details.tabId];
    if (!entry || !entry.mainFrameUrl || !entry.mainFrameUrl.startsWith("https:")) return;
    if (!details.url.startsWith("http:")) return;

    if (ACTIVE_MIXED_TYPES.has(details.type)) {
      entry.mixedActive++;
    } else {
      entry.mixedPassive++;
    }
  },
  { urls: ["<all_urls>"] }
);

// Inspect only the main page response so subresources do not overwrite page-level headers.
chrome.webRequest.onHeadersReceived.addListener(
  async (details) => {
    if (!details.responseHeaders || details.tabId < 0 || details.type !== "main_frame") return;

    const entry = entryFor(details.tabId);
    entry.headers = normalizeHeaders(details.responseHeaders);
    entry.cookies = parseSetCookieHeaders(details.responseHeaders);
    entry.mainFrameUrl = details.url;
    entry.infrastructure.tlsCertificate = await getTlsCertificateInfo(details.requestId);
  },
  { urls: ["<all_urls>"], types: ["main_frame"] },
  [...RESPONSE_HEADER_OPTIONS, "blocking"]
);

chrome.webRequest.onBeforeRedirect.addListener(
  (details) => {
    if (details.tabId < 0 || details.type !== "main_frame") return;

    const entry = entryFor(details.tabId);
    entry.mainRequestId = details.requestId;
    entry.redirects.push({
      from: details.url,
      to: details.redirectUrl,
      statusCode: details.statusCode
    });
  },
  { urls: ["<all_urls>"], types: ["main_frame"] }
);

chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (details.tabId < 0 || details.type !== "main_frame") return;

    const entry = entryFor(details.tabId);
    if (entry.requestStartedAt) {
      entry.responseTimeMs = Math.max(0, Math.round(details.timeStamp - entry.requestStartedAt));
    }
  },
  { urls: ["<all_urls>"], types: ["main_frame"] }
);

chrome.tabs.onRemoved.addListener((tabId) => {
  delete cache[tabId];
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_PAGE_SECURITY") {
    sendResponse(cache[msg.tabId] || defaultEntry());
  }

  if (msg.type === "SCAN_URL") {
    scanUrl(msg.url)
      .then((result) => sendResponse({ ok: true, ...result }))
      .catch(() => sendResponse({ ok: false }));

    return true;
  }
});
