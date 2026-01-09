const https = require('https');
const http = require('http');

async function sendWebhook(url, results) {
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

  return send(url, payload);
}

function formatDiscord(results) {
  const { summary, threats, target } = results;
  
  const color = summary.riskLevel === 'CRITICAL' ? 0xe74c3c
              : summary.riskLevel === 'HIGH' ? 0xe67e22
              : summary.riskLevel === 'MEDIUM' ? 0xf1c40f
              : summary.riskLevel === 'LOW' ? 0x3498db
              : 0x2ecc71;

  const criticalThreats = threats
    .filter(t => t.severity === 'CRITICAL')
    .slice(0, 5)
    .map(t => `- ${t.message}`)
    .join('\n');

  const fields = [
    {
      name: 'Score de risque',
      value: `**${summary.riskScore}/100** (${summary.riskLevel})`,
      inline: true
    },
    {
      name: 'Menaces',
      value: `${summary.critical} CRITICAL\n${summary.high} HIGH\n${summary.medium} MEDIUM`,
      inline: true
    },
    {
      name: 'Total',
      value: `**${summary.total}** menace(s)`,
      inline: true
    }
  ];

  // Ajouter les menaces critiques si présentes
  if (criticalThreats) {
    fields.push({
      name: 'Menaces critiques',
      value: criticalThreats || 'Aucune',
      inline: false
    });
  }

  return {
    embeds: [{
      title: 'MUAD\'DIB Security Scan',
      description: `Scan de **${target}**`,
      color: color,
      fields: fields,
      footer: {
        text: 'MUAD\'DIB - Supply-chain threat detection'
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
          text: `*Cible:*\n${target}`
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

  // Ajouter les menaces critiques si présentes
  if (criticalList) {
    blocks.push({
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `*Menaces critiques:*\n${criticalList}`
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

function send(url, payload) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const protocol = urlObj.protocol === 'https:' ? https : http;

    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    };

    const req = protocol.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ success: true, status: res.statusCode });
        } else {
          reject(new Error(`Webhook failed: HTTP ${res.statusCode}`));
        }
      });
    });

    req.on('error', reject);
    req.write(JSON.stringify(payload));
    req.end();
  });
}

module.exports = { sendWebhook };