# Attack Path Simulator - How to Use

## Overview

The Attack Path Simulator visualizes potential attack paths through your network, showing how an attacker could move from an entry point to critical assets.

## Step-by-Step Instructions

### 1. **Navigate to Attack Simulator**

- Click on **"Attack Simulator"** in the left sidebar
- You should see the Attack Path Simulator page

### 2. **Select Attack Type** (Top Right Dropdown)

- **Ransomware** - Simulates ransomware propagation
- **APT** - Advanced Persistent Threat scenario
- **Insider Threat** - Internal threat simulation
- **DDoS** - Distributed Denial of Service attack
- Default: Ransomware

Example: Choose "Ransomware" for a typical attack scenario

### 3. **Click "Start Simulation"** (Green Button)

- Click the **green "Start Simulation"** button
- The system will:
  - Analyze your network topology
  - Find attack paths from the entry point
  - Calculate blast radius (affected assets)
  - Assess risk level

### 4. **View Results**

#### **Attack Path Visualization** (Left Panel)

Shows the attack paths found with:

- **Path nodes** - Red (start) → Gray (intermediate) → Purple (target)
- **Risk Score** - Color coded: Red (8+), Yellow (5-7), Green (<5)
- **Mitigations** - Recommended fixes for each path

#### **Impact Estimation** (Right Panel)

- **Business Impact** - HIGH/MEDIUM/LOW
- **Financial Loss** - Estimated revenue impact ($2.4M)
- **Assets at Risk** - Number of critical systems affected (47)
- **Recovery Time** - Estimated downtime (72 hours)

#### **MITRE ATT&CK Tactics** (Bottom)

- Shows attack phases with number of techniques
- **Blue highlighted** = Active in this simulation
- **Gray** = Not currently active

### 5. **Control Buttons**

- **Start Simulation** - Begin attack simulation
- **Pause** - Pause the simulation
- **Reset** - Clear results and start over

---

## Understanding the Results

### Attack Paths Found

```
Path Example:
external_firewall → vpn_gateway → ad_server → db_server_1
Risk: 6.0/10
```

This means:

- An attacker starting at `external_firewall`
- Can reach `vpn_gateway` in 1 hop
- Then reach AD server in another hop
- Finally reach the database in a 3rd hop
- **Risk Score 6.0** means moderate risk (on a 1-10 scale)

### Blast Radius

The list of assets that could be compromised within 4 network hops from the entry point. These are the critical assets you need to protect.

### Risk Assessment

- **CRITICAL** - Multiple paths to critical assets
- **HIGH** - Direct access to important systems
- **MEDIUM** - Requires lateral movement
- **LOW** - Limited impact potential

---

## Troubleshooting

### Error: "Not Found"

- ✅ Backend is running on `http://localhost:8000`
- ✅ Frontend is running on `http://localhost:3000`
- ✅ Both services are accessible

**Fix**: Refresh the page and try again

### Error: "Network error"

- Make sure backend is running: `python -m uvicorn app.main:app --host 0.0.0.0 --port 8000`
- Make sure frontend is running: `npm run dev`
- Check that both are on correct ports (8000 for backend, 3000 for frontend)

### No Results Displayed

- Wait for the simulation to complete (progress shown with spinner)
- Check browser console for errors (F12)
- Verify the digital twin has assets loaded

---

## Example Scenarios

### Scenario 1: Ransomware Attack

1. Select "Ransomware" from dropdown
2. Click "Start Simulation"
3. View how ransomware spreads through SMB/network shares

### Scenario 2: APT Attack

1. Select "APT" from dropdown
2. Review targeted attack paths
3. Check for sophisticated lateral movement

### Scenario 3: Insider Threat

1. Select "Insider Threat"
2. See data exfiltration paths
3. Review privileged access routes

---

## Key Metrics

| Metric              | Meaning                                      |
| ------------------- | -------------------------------------------- |
| **Paths Found**     | Number of different attack routes discovered |
| **Blast Radius**    | Total assets that could be affected          |
| **Risk Score**      | 1-10 scale: higher = more dangerous          |
| **Risk Assessment** | Overall impact if attack succeeds            |
| **Recovery Time**   | Hours needed to restore normal operations    |

---

## Recommendations

For each simulation, implement the **recommended mitigations**:

- Network segmentation
- Zero-trust access controls
- Enhanced monitoring
- EDR solutions
- Multi-factor authentication
- Privileged access management

---

## Questions?

Check the browser console (F12 → Console tab) for detailed error messages if something doesn't work.
