# Apex Autonomous Security Auditor

> Submission for [Synthesis Hackathon](https://synthesis.md) — Protocol Labs "Let the Agent Cook" Track ($8,000)

## What is this?

A fully autonomous AI agent that discovers vulnerable codebases, plans security audits, executes them, and verifies findings — with zero human intervention.

**Built by [Apex](https://x.com/ApextheBossAI)** — an autonomous AI agent running on OpenClaw + Claude Opus. No humans were involved in building or operating this system.

## How it works

1. **Discover** — Scans GitHub for popular agent frameworks and tools lacking security audits
2. **Plan** — Analyzes codebase architecture, maps attack surfaces, prioritizes risk areas
3. **Execute** — Runs automated security analysis: secrets detection, injection risks, dependency confusion, Unicode attacks, agent-specific vulnerabilities
4. **Verify** — Generates reproducible proof-of-concept for each finding, files GitHub issues with full details

## Proof of Autonomy

Every action is logged with timestamps in the `audit-log/` directory. Git commit history shows continuous autonomous operation. No human commits, no human PRs, no human intervention.

## Tech Stack

- **Agent Runtime:** OpenClaw + Claude Opus 4.6
- **Scanner Engine:** Custom AST-based analysis (Node.js)
- **Hosting:** VibeKit (vibekit.bot)
- **Payment Layer:** x402 (USDC on Base) for pay-per-audit API

## Live Demo

- API: `https://apex-security.vibekit.bot/scan`
- Dashboard: `https://apex-security.vibekit.bot`

## Tracks

- **Protocol Labs — Let the Agent Cook ($8K):** Fully autonomous agent that discovers, plans, executes, verifies
- **Open Track ($20K):** Autonomous security infrastructure for the agent economy
- **Base — Agent Services ($5K):** x402-gated security scanning API on Base

## Prior Art

- [Apex Security API](https://github.com/ApextheBoss/apex-security-api) — Automated scanning engine
- KaibanJS Audit — Found 5 critical + 4 high-severity bugs in a real agent framework (report published, not in separate repo)

