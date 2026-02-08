#!/usr/bin/env node

/**
 * Converts npm/pnpm audit JSON output to SARIF format for GitHub Security tab integration.
 *
 * Usage: node audit-to-sarif.js audit.json > audit.sarif
 */

const fs = require("fs");

const inputFile = process.argv[2];

if (!inputFile) {
  console.error("Usage: node audit-to-sarif.js <audit.json>");
  process.exit(1);
}

let auditJson;
try {
  auditJson = JSON.parse(fs.readFileSync(inputFile, "utf8"));
} catch (error) {
  // If file doesn't exist or is invalid, output empty SARIF
  console.log(
    JSON.stringify(
      {
        version: "2.1.0",
        $schema: "https://json.schemastore.org/sarif-2.1.0.json",
        runs: [
          {
            tool: {
              driver: {
                name: "pnpm-audit",
                version: "1.0.0",
                rules: [],
              },
            },
            results: [],
          },
        ],
      },
      null,
      2,
    ),
  );
  process.exit(0);
}

const sarif = {
  version: "2.1.0",
  $schema: "https://json.schemastore.org/sarif-2.1.0.json",
  runs: [
    {
      tool: {
        driver: {
          name: "pnpm-audit",
          version: "1.0.0",
          informationUri: "https://docs.npmjs.com/cli/v10/commands/npm-audit",
          rules: [],
        },
      },
      results: [],
    },
  ],
};

// Map severity to SARIF level
function mapSeverityToLevel(severity) {
  switch (severity) {
    case "critical":
      return "error";
    case "high":
      return "error";
    case "moderate":
      return "warning";
    case "low":
      return "note";
    default:
      return "none";
  }
}

// Map severity to SARIF security-severity score
function mapSeverityToScore(severity) {
  switch (severity) {
    case "critical":
      return "9.0";
    case "high":
      return "7.0";
    case "moderate":
      return "5.0";
    case "low":
      return "3.0";
    default:
      return "1.0";
  }
}

// Handle pnpm audit format (advisories object)
if (auditJson.advisories) {
  for (const [id, advisory] of Object.entries(auditJson.advisories)) {
    const ruleId = `npm-advisory-${id}`;

    sarif.runs[0].tool.driver.rules.push({
      id: ruleId,
      name: advisory.title || `Advisory ${id}`,
      shortDescription: { text: advisory.title || `Security advisory ${id}` },
      fullDescription: { text: advisory.overview || advisory.title || "" },
      helpUri: advisory.url || `https://www.npmjs.com/advisories/${id}`,
      properties: {
        severity: advisory.severity,
        "security-severity": mapSeverityToScore(advisory.severity),
      },
    });

    sarif.runs[0].results.push({
      ruleId: ruleId,
      level: mapSeverityToLevel(advisory.severity),
      message: {
        text: `${advisory.module_name}@${advisory.vulnerable_versions}: ${advisory.title}`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: "package.json" },
            region: { startLine: 1 },
          },
        },
      ],
    });
  }
}

// Handle npm audit v2 format (vulnerabilities object)
if (auditJson.vulnerabilities) {
  for (const [pkgName, vuln] of Object.entries(auditJson.vulnerabilities)) {
    if (!vuln.via || !Array.isArray(vuln.via)) continue;

    for (const via of vuln.via) {
      // Skip if via is just a string (dependency chain reference)
      if (typeof via === "string") continue;

      const ruleId = `npm-advisory-${via.source || pkgName}`;
      const existingRule = sarif.runs[0].tool.driver.rules.find((r) => r.id === ruleId);

      if (!existingRule) {
        sarif.runs[0].tool.driver.rules.push({
          id: ruleId,
          name: via.title || `Advisory for ${pkgName}`,
          shortDescription: { text: via.title || `Security vulnerability in ${pkgName}` },
          fullDescription: { text: via.title || "" },
          helpUri: via.url || `https://www.npmjs.com/package/${pkgName}`,
          properties: {
            severity: via.severity || vuln.severity,
            "security-severity": mapSeverityToScore(via.severity || vuln.severity),
          },
        });
      }

      sarif.runs[0].results.push({
        ruleId: ruleId,
        level: mapSeverityToLevel(via.severity || vuln.severity),
        message: {
          text: `${pkgName}@${via.range || vuln.range}: ${via.title || "Security vulnerability"}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: "package.json" },
              region: { startLine: 1 },
            },
          },
        ],
      });
    }
  }
}

console.log(JSON.stringify(sarif, null, 2));
