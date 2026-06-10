# Template Validation Signal Report

This report separates template behavior from Shodan discovery quality.

## Legend

- `LIVE TP`: Nuclei matched at least one live candidate.
- `CANDIDATES NO MATCH`: Shodan returned product-looking candidates, but the template did not match. This is the bucket to manually inspect or patch.
- `SHODAN GAP`: Shodan did not return usable candidates. This is not a template failure by itself; it means live TP could not be established from Shodan.

## Executive Signal

- Total scoped templates: 64
- Confirmed live TP from current report: 30
- No false positives remaining in focused 50-target rerun for edited FP templates: yes
- Re-audited unresolved templates in this report: 11

## Re-Audited Unresolved Templates

| Template | Verdict | Strong candidates | Matches | Evidence signal | Notes |
|---|---|---:|---:|---|---|
| `utils/nuclei/templates/discover/application/collaborationapplication/microsoft-exchange-owa.yaml` | **LIVE TP** | 12 | 12 | Exchange OWA commonly exposes X-OWA-Version/X-FEServer headers and OWA login body markers such as owa/auth and owaLgnBdy. | Nuclei matched 12 of 12 stronger Shodan candidates. |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/advantech-webaccess-scada.yaml` | **LIVE TP** | 12 | 2 | Template checks Advantech WebAccess, WebAccess/SCADA, and BroadWeb markers, which are product-specific UI strings. | Nuclei matched 2 of 12 stronger Shodan candidates. |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/codesys-webvisu.yaml` | **LIVE TP** | 12 | 4 | Template checks CODESYS WebVisu and CoDeSys WebVisualization title/vendor markers. | Nuclei matched 4 of 12 stronger Shodan candidates. |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/ge-proficy-webspace.yaml` | **LIVE TP** | 12 | 5 | Template checks Proficy WebSpace title/product branding and the ProficyWebSpace/WebSpace paths. | Nuclei matched 5 of 12 stronger Shodan candidates. |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/inductive-automation-ignition-gateway.yaml` | **CANDIDATES NO MATCH** | 12 | 0 | Template checks Ignition Gateway title with Inductive Automation vendor marker. | Shodan returned 12 candidates from stronger product queries, but the template did not match them. |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/siemens-simatic-hmi-web.yaml` | **LIVE TP** | 12 | 8 | Template checks a Siemens SIMATIC HMI title marker. | Nuclei matched 8 of 12 stronger Shodan candidates. |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/siemens-wincc-unified.yaml` | **CANDIDATES NO MATCH** | 12 | 0 | Template checks Siemens plus WinCC Unified title markers. | Shodan returned 12 candidates from stronger product queries, but the template did not match them. |
| `utils/nuclei/templates/discover/application/networkedgeapplication/fortinet-fortigate-sslvpn.yaml` | **LIVE TP** | 12 | 9 | Template checks FortiGate SSL-VPN wording, /remote/login, and Fortinet language cookie/header markers. | Nuclei matched 9 of 12 stronger Shodan candidates. |
| `utils/nuclei/templates/discover/application/networkmanagementsystem/aruba-instant.yaml` | **LIVE TP** | 12 | 12 | Template checks Aruba Instant title/login and ArubaNetworks virtual controller markers. | Nuclei matched 12 of 12 stronger Shodan candidates. |
| `utils/nuclei/templates/discover/application/networkmanagementsystem/asuswrt-router-web-ui.yaml` | **LIVE TP** | 12 | 1 | Template checks ASUS Wireless Router title, ASUSWRT login path, and asus_token markers. | Nuclei matched 1 of 12 stronger Shodan candidates. |
| `utils/nuclei/templates/discover/application/networkmanagementsystem/ruckus-wireless-management.yaml` | **LIVE TP** | 12 | 12 | Template checks Ruckus plus ZoneDirector/SmartZone/Unleashed or Ruckus Wireless login markers. | Nuclei matched 12 of 12 stronger Shodan candidates. |

## Live Matches Found In Re-Audit

### Microsoft Exchange OWA
- `https://185.163.63.60/owa/auth/logon.aspx?url=https%3a%2f%2f185.163.63.60%2fowa%2f&reason=0`
- `https://20.57.141.3:443/owa/`
- `https://185.241.20.110/owa/auth/logon.aspx?url=https%3a%2f%2f185.241.20.110%2fowa%2f&reason=0`
- `https://194.132.108.11:443/owa/`
- `https://200.169.4.10/owa/auth/logon.aspx?url=https%3a%2f%2f200.169.4.10%2fowa%2f&reason=0`

### Advantech WebAccess SCADA
- `http://153.142.33.8:80/broadWeb/bwRoot.asp?username=admin`
- `http://47.112.19.200:16017/broadWeb/bwRoot.asp`

### CODESYS WebVisu
- `http://62.100.148.187:8080`
- `http://139.28.40.194:8080`
- `http://203.181.24.187:8080`
- `https://203.181.24.192:443/webvisu/webvisu.htm`

### GE Proficy WebSpace
- `http://213.147.102.156:491`
- `http://203.70.231.128:491`
- `http://125.18.4.190:491`
- `http://45.11.63.178:491`
- `http://217.160.76.161:491`

### Siemens SIMATIC HMI Web
- `http://91.182.72.61:8080`
- `https://37.84.225.241:443`
- `https://2.40.140.66:443`
- `https://212.93.127.197:443`
- `https://37.84.61.64:443`

### Fortinet FortiGate SSL-VPN
- `http://3.137.185.136:80`
- `https://138.197.37.197:443/login`
- `https://198.58.114.145:10443`
- `https://161.35.211.226:443`
- `http://152.42.242.201:8013/remote/login/`

### Aruba Instant
- `http://108.253.173.43:8080`
- `http://74.78.90.211:8080`
- `http://82.198.75.229:8080`
- `http://118.45.120.213:8080`
- `http://210.204.180.111:8080`

### ASUSWRT Router UI
- `http://16.174.30.70:49686/chat`

### Ruckus Wireless Management
- `https://177.92.82.99:2376/admin/login.jsp`
- `https://177.92.82.99:8889/admin/login.jsp`
- `https://177.92.82.99:8140/admin/login.jsp`
- `https://177.92.82.99:9095/admin/login.jsp`
- `https://177.92.82.99:9398/admin/login.jsp`

## Candidate Queries And Outcomes

### Microsoft Exchange OWA - LIVE TP
Template: `utils/nuclei/templates/discover/application/collaborationapplication/microsoft-exchange-owa.yaml`

| Query | Added candidates | Shodan total |
|---|---:|---:|
| `http.headers.x-owa-version:*` | 0 | 0 |
| `http.headers.x-feserver:*` | 0 | 0 |
| `http.html:"owa/auth" "Microsoft Exchange"` | 12 | 74709 |

### Advantech WebAccess SCADA - LIVE TP
Template: `utils/nuclei/templates/discover/application/industrialcontrolsystem/advantech-webaccess-scada.yaml`

| Query | Added candidates | Shodan total |
|---|---:|---:|
| `http.html:"Advantech WebAccess"` | 12 | 838 |

### CODESYS WebVisu - LIVE TP
Template: `utils/nuclei/templates/discover/application/industrialcontrolsystem/codesys-webvisu.yaml`

| Query | Added candidates | Shodan total |
|---|---:|---:|
| `http.html:"CODESYS WebVisu"` | 8 | 8 |
| `http.html:"CoDeSys WebVisualization"` | 4 | 318 |

### GE Proficy WebSpace - LIVE TP
Template: `utils/nuclei/templates/discover/application/industrialcontrolsystem/ge-proficy-webspace.yaml`

| Query | Added candidates | Shodan total |
|---|---:|---:|
| `http.html:"Proficy WebSpace"` | 12 | 22 |

### Inductive Automation Ignition Gateway - CANDIDATES NO MATCH
Template: `utils/nuclei/templates/discover/application/industrialcontrolsystem/inductive-automation-ignition-gateway.yaml`

| Query | Added candidates | Shodan total |
|---|---:|---:|
| `http.title:"Ignition Gateway"` | 12 | 3554 |

### Siemens SIMATIC HMI Web - LIVE TP
Template: `utils/nuclei/templates/discover/application/industrialcontrolsystem/siemens-simatic-hmi-web.yaml`

| Query | Added candidates | Shodan total |
|---|---:|---:|
| `http.title:"Siemens SIMATIC HMI"` | 12 | 37 |

### Siemens WinCC Unified - CANDIDATES NO MATCH
Template: `utils/nuclei/templates/discover/application/industrialcontrolsystem/siemens-wincc-unified.yaml`

| Query | Added candidates | Shodan total |
|---|---:|---:|
| `http.title:"WinCC Unified"` | 12 | 756 |

### Fortinet FortiGate SSL-VPN - LIVE TP
Template: `utils/nuclei/templates/discover/application/networkedgeapplication/fortinet-fortigate-sslvpn.yaml`

| Query | Added candidates | Shodan total |
|---|---:|---:|
| `http.html:"Fortigate SSL-VPN"` | 6 | 6 |
| `http.html:"/remote/login" http.html:"Fortinet"` | 3 | 3 |
| `http.headers.set-cookie:"SVPNCOOKIE"` | 0 | 0 |
| `http.headers.set-cookie:"fgt"` | 0 | 0 |
| `ssl.cert.subject.cn:"Fortinet"` | 3 | 179 |

### Aruba Instant - LIVE TP
Template: `utils/nuclei/templates/discover/application/networkmanagementsystem/aruba-instant.yaml`

| Query | Added candidates | Shodan total |
|---|---:|---:|
| `http.title:"Aruba Instant"` | 12 | 205 |

### ASUSWRT Router UI - LIVE TP
Template: `utils/nuclei/templates/discover/application/networkmanagementsystem/asuswrt-router-web-ui.yaml`

| Query | Added candidates | Shodan total |
|---|---:|---:|
| `http.title:"ASUS Wireless Router"` | 12 | 7780 |

### Ruckus Wireless Management - LIVE TP
Template: `utils/nuclei/templates/discover/application/networkmanagementsystem/ruckus-wireless-management.yaml`

| Query | Added candidates | Shodan total |
|---|---:|---:|
| `http.html:"Ruckus" http.html:"ZoneDirector"` | 12 | 2580 |
