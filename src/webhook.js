const https = require('https');
const http = require('http');
const dns = require('dns');

// Allowed domains for webhooks (SSRF security)
const ALLOWED_WEBHOOK_DOMAINS = [
  'discord.com',
  'discordapp.com',
  'hooks.slack.com'
];

// Private IP ranges for SSRF protection (checked against resolved IPs)
const PRIVATE_IP_PATTERNS = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
  /^192\.168\./,
  /^0\./,
  /^169\.254\./,
  /^::1$/,
  /^::ffff:127\./,
  /^fc00:/,
  /^fe80:/
];

/**
 * Validates that a webhook URL is allowed
 * @param {string} url - Webhook URL
 * @returns {{valid: boolean, error?: string}} Validation result
 */
function validateWebhookUrl(url) {
  try {
    const urlObj = new URL(url);

    // Check protocol (HTTPS required, no exceptions)
    if (urlObj.protocol !== 'https:') {
      return { valid: false, error: 'HTTPS required for webhooks' };
    }

    // Check that the domain is allowed (no localhost exemption)
    const hostname = urlObj.hostname.toLowerCase();
    const isAllowed = ALLOWED_WEBHOOK_DOMAINS.some(domain =>
      hostname === domain || hostname.endsWith('.' + domain)
    );

    if (!isAllowed) {
      return { valid: false, error: `Domain not allowed: ${hostname}. Allowed domains: ${ALLOWED_WEBHOOK_DOMAINS.join(', ')}` };
    }

    // Block private IP addresses (SSRF) — checks literal IP hostnames
    if (PRIVATE_IP_PATTERNS.some(pattern => pattern.test(hostname))) {
      return { valid: false, error: 'Private IP addresses not allowed' };
    }

    return { valid: true };
  } catch (e) {
    return { valid: false, error: `Invalid URL: ${e.message}` };
  }
}

async function sendWebhook(url, results, options = {}) {
  // Validate URL before sending
  const validation = validateWebhookUrl(url);
  if (!validation.valid) {
    throw new Error(`Webhook blocked: ${validation.error}`);
  }

  // DNS resolution check: verify ALL resolved IPs (IPv4 + IPv6) are not private (SSRF via DNS rebinding)
  // Pin the first resolved IPv4 and use it for the actual connection (WHK-001)
  const urlObj = new URL(url);
  let resolvedAddress;
  try {
    const [ipv4Addresses, ipv6Addresses] = await Promise.all([
      dns.promises.resolve4(urlObj.hostname).catch(() => []),
      dns.promises.resolve6(urlObj.hostname).catch(() => [])
    ]);
    const allAddresses = [...ipv4Addresses, ...ipv6Addresses];
    if (allAddresses.length === 0) {
      throw new Error(`Webhook blocked: no DNS records found for ${urlObj.hostname}`);
    }
    for (const address of allAddresses) {
      if (PRIVATE_IP_PATTERNS.some(pattern => pattern.test(address))) {
        throw new Error(`Webhook blocked: hostname ${urlObj.hostname} resolves to private IP ${address}`);
      }
    }
    resolvedAddress = ipv4Addresses[0] || null;
  } catch (e) {
    if (e.message.startsWith('Webhook blocked')) throw e;
    throw new Error(`Webhook blocked: DNS resolution failed for ${urlObj.hostname}`);
  }

  // rawPayload: send the results object directly as the payload (for pre-built embeds)
  if (options.rawPayload) {
    return send(url, results, resolvedAddress);
  }

  const isDiscord = url.includes('discord.com');
  const isSlack = url.includes('hooks.slack.com');

  let payload;

  if (isDiscord) {
    payload = formatDiscord(results);
  } else if (isSlack) {
    payload = formatSlack(results);
  } else {
    payload = formatGeneric(results);
  }

  return send(url, payload, resolvedAddress);
}

function formatDiscord(results) {
  const { summary, threats, target } = results;

  const color = summary.riskLevel === 'CRITICAL' ? 0xe74c3c
              : summary.riskLevel === 'HIGH' ? 0xe67e22
              : summary.riskLevel === 'MEDIUM' ? 0xf1c40f
              : summary.riskLevel === 'LOW' ? 0x3498db
              : 0x2ecc71;

  const emoji = summary.riskLevel === 'CRITICAL' ? '\uD83D\uDD34'
              : summary.riskLevel === 'HIGH' ? '\uD83D\uDFE0'
              : summary.riskLevel === 'MEDIUM' ? '\uD83D\uDFE1'
              : '';

  const criticalThreats = threats
    .filter(t => t.severity === 'CRITICAL')
    .slice(0, 5)
    .map(t => `- ${t.message}`)
    .join('\n');

  const fields = [
    {
      name: 'Risk Score',
      value: `**${summary.riskScore}/100** (${summary.riskLevel})`,
      inline: true
    },
    {
      name: 'Threats',
      value: `${summary.critical} CRITICAL\n${summary.high} HIGH\n${summary.medium} MEDIUM`,
      inline: true
    },
    {
      name: 'Total',
      value: `**${summary.total}** threat(s)`,
      inline: true
    }
  ];

  // Add ecosystem field if available
  if (results.ecosystem) {
    fields.push({
      name: 'Ecosystem',
      value: results.ecosystem.toUpperCase(),
      inline: true
    });
  }

  // Add package link if ecosystem info is available
  if (results.ecosystem && target) {
    // Extract package name from target (format: "ecosystem/name@version")
    const nameMatch = target.match(/^(?:npm|pypi)\/(.+?)(?:@.*)?$/);
    if (nameMatch) {
      const pkgName = nameMatch[1];
      const link = results.ecosystem === 'npm'
        ? `https://www.npmjs.com/package/${pkgName}`
        : `https://pypi.org/project/${pkgName}/`;
      fields.push({
        name: 'Package Link',
        value: `[${pkgName}](${link})`,
        inline: true
      });
    }
  }

  // Add critical threats if present
  if (criticalThreats) {
    fields.push({
      name: 'Critical Threats',
      value: criticalThreats || 'None',
      inline: false
    });
  }

  // Add sandbox field if sandbox results are present
  if (results.sandbox) {
    fields.push({
      name: 'Sandbox',
      value: `Score: **${results.sandbox.score}/100** (${results.sandbox.severity})`,
      inline: false
    });
  }

  const titlePrefix = emoji ? `${emoji} ` : '';
  const ts = results.timestamp ? new Date(results.timestamp) : new Date();
  const readableTime = ts.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');

  return {
    embeds: [{
      title: `${titlePrefix}MUAD'DIB Security Scan`,
      description: `Scan of **${target}**`,
      color: color,
      fields: fields,
      footer: {
        text: `MUAD'DIB - Supply-chain threat detection | ${readableTime}`
      },
      timestamp: results.timestamp
    }]
  };
}

function formatSlack(results) {
  const { summary, threats, target } = results;

  const emoji = summary.riskLevel === 'CRITICAL' ? ':rotating_light:'
              : summary.riskLevel === 'HIGH' ? ':warning:'
              : summary.riskLevel === 'MEDIUM' ? ':large_yellow_circle:'
              : summary.riskLevel === 'LOW' ? ':information_source:'
              : ':white_check_mark:';

  const criticalList = threats
    .filter(t => t.severity === 'CRITICAL')
    .slice(0, 5)
    .map(t => `• ${t.message}`)
    .join('\n');

  const blocks = [
    {
      type: 'header',
      text: {
        type: 'plain_text',
        text: `${emoji} MUAD'DIB Security Scan`
      }
    },
    {
      type: 'section',
      fields: [
        {
          type: 'mrkdwn',
          text: `*Target:*\n${target}`
        },
        {
          type: 'mrkdwn',
          text: `*Score:*\n${summary.riskScore}/100 (${summary.riskLevel})`
        }
      ]
    },
    {
      type: 'section',
      fields: [
        {
          type: 'mrkdwn',
          text: `*CRITICAL:* ${summary.critical}`
        },
        {
          type: 'mrkdwn',
          text: `*HIGH:* ${summary.high}`
        },
        {
          type: 'mrkdwn',
          text: `*MEDIUM:* ${summary.medium}`
        },
        {
          type: 'mrkdwn',
          text: `*Total:* ${summary.total}`
        }
      ]
    }
  ];

  // Add critical threats if present
  if (criticalList) {
    blocks.push({
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `*Critical Threats:*\n${criticalList}`
      }
    });
  }

  return { blocks };
}

function formatGeneric(results) {
  return {
    tool: 'MUADDIB',
    target: results.target,
    timestamp: results.timestamp,
    summary: results.summary,
    threats: results.threats.map(t => ({
      type: t.type,
      severity: t.severity,
      message: t.message,
      file: t.file
    }))
  };
}

const MAX_RESPONSE_SIZE = 1024 * 1024; // 1MB

function send(url, payload, resolvedAddress) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const protocol = urlObj.protocol === 'https:' ? https : http;

    const body = JSON.stringify(payload);
    const options = {
      hostname: resolvedAddress || urlObj.hostname,
      port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'Host': urlObj.hostname
      },
      servername: urlObj.hostname
    };

    const req = protocol.request(options, (res) => {
      let data = '';
      let size = 0;
      res.on('data', chunk => {
        size += chunk.length;
        if (size > MAX_RESPONSE_SIZE) {
          res.destroy();
          reject(new Error('Webhook response exceeded 1MB limit'));
          return;
        }
        data += chunk;
      });
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ success: true, status: res.statusCode });
        } else {
          reject(new Error(`Webhook failed: HTTP ${res.statusCode}`));
        }
      });
    });

    req.setTimeout(10000, () => {
      req.destroy();
      reject(new Error('Webhook timeout after 10s'));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

module.exports = { sendWebhook, validateWebhookUrl, formatDiscord, formatSlack, formatGeneric };