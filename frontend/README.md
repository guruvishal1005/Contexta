# RiskLens AI – Context-Aware Threat Intelligence Platform

A production-quality, enterprise-grade SOC dashboard for threat intelligence and business risk management.

## Features

- **Real-time Threat Monitoring**: Live alert feed with severity-based prioritization
- **Risk Analytics**: Comprehensive risk scoring and trend analysis
- **Attack Simulation**: MITRE ATT&CK-based attack path modeling
- **Executive Dashboard**: Business-focused risk metrics and compliance tracking
- **Department Risk Heatmap**: Organizational risk visibility
- **Threat Intelligence**: AI-powered threat correlation and insights

## Tech Stack

- **Framework**: Next.js 14 (React 18)
- **Styling**: TailwindCSS
- **Charts**: Recharts
- **Icons**: Lucide React
- **Language**: TypeScript

## Getting Started

### Installation

```bash
npm install
```

### Development

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### Build

```bash
npm run build
npm start
```

## Project Structure

```
├── app/
│   ├── layout.tsx          # Root layout
│   ├── page.tsx            # Main dashboard page
│   └── globals.css         # Global styles
├── components/
│   ├── TopNavBar.tsx       # Top navigation
│   ├── Sidebar.tsx         # Left sidebar navigation
│   ├── Dashboard.tsx       # Main dashboard view
│   ├── AttackSimulator.tsx # Attack simulation view
│   ├── ExecutiveView.tsx   # Executive dashboard
│   └── dashboard/
│       ├── KPICards.tsx
│       ├── TopRisksTable.tsx
│       ├── RiskTrendChart.tsx
│       ├── VulnerabilityChart.tsx
│       ├── DepartmentHeatmap.tsx
│       ├── AlertFeed.tsx
│       ├── ThreatInsights.tsx
│       └── RecommendedActions.tsx
├── tailwind.config.js
├── tsconfig.json
└── package.json
```

## Design Philosophy

- **Enterprise-grade**: Professional SOC aesthetic
- **Information density**: Optimized for analyst workflows
- **Light theme**: Reduced eye strain for long sessions
- **Minimal animations**: Performance-focused
- **Responsive**: Desktop-first, tablet-compatible

## License

Proprietary - RiskLens AI Platform
