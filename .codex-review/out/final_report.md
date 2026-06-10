# Template Validation Signal Report

This report is organized by decision signal, not raw scanner status.

## Summary

- Scoped templates: 64
- Syntax valid: 64/64
- False-positive status: PASS for all rows after targeted fixes
- Readability pass: converted simple positive DSL `contains(...)` blocks to standard Nuclei `word` matchers where behavior/content could be preserved.
- DSL intentionally retained for status-code guards, negations, mixed header+body branches, and complex boolean logic.
- Live TP confirmed: 40/64
- Shodan gaps with no live TP evidence: 23
- Noisy Shodan candidates with no live TP: 1

## What The Signals Mean

- `LIVE_TP`: template matched at least one live target.
- `LIVE_TP_FIXED_FP`: template had a false positive, was tightened, and still matched live true-positive candidates.
- `SHODAN_GAP_NO_LIVE_TP`: Shodan did not produce usable candidates. This is a discovery gap, not a template failure.
- `NOISY_CANDIDATES_NO_LIVE_TP`: Shodan returned candidates, but fetched evidence was unrelated/noisy and the template correctly did not match.

## Fixed False Positives, Still Live TP (3)

| Template | Live matches | Example/evidence | Action |
|---|---:|---|---|
| `utils/nuclei/templates/discover/application/filetransferapplication/crushftp.yaml` | 5/5 | Fixed FP and reconfirmed 5/5 live Shodan candidates. | keep fixed template |
| `utils/nuclei/templates/discover/application/filetransferapplication/globalscape-eft.yaml` | 5/5 | Fixed FP and reconfirmed 5/5 live Shodan candidates. | keep fixed template |
| `utils/nuclei/templates/discover/application/outofbandapplication/hpe-ilo.yaml` | 5/5 | Fixed FP and reconfirmed 5/5 live Shodan candidates. | keep fixed template |

## Live TP Confirmed (37)

| Template | Live matches | Example/evidence | Action |
|---|---:|---|---|
| `utils/nuclei/templates/discover/application/collaborationapplication/atlassian-confluence.yaml` | >=5 | http://35.183.113.183:12320/login.action | keep template |
| `utils/nuclei/templates/discover/application/collaborationapplication/atlassian-jira.yaml` | >=2 | https://212.227.23.140:443 | keep template |
| `utils/nuclei/templates/discover/application/collaborationapplication/citrix-sharefile.yaml` | >=3 | http://18.118.71.239:80 | keep template |
| `utils/nuclei/templates/discover/application/collaborationapplication/microsoft-exchange-owa.yaml` | 12/12 | https://185.163.63.60/owa/auth/logon.aspx | keep template |
| `utils/nuclei/templates/discover/application/collaborationapplication/microsoft-sharepoint.yaml` | >=1 | https://110.170.53.81:443/_layouts/15/start.aspx | keep template |
| `utils/nuclei/templates/discover/application/collaborationapplication/nextcloud.yaml` | >=4 | https://209.161.6.12:443 | keep template |
| `utils/nuclei/templates/discover/application/collaborationapplication/opentext-content-server.yaml` | >=1 | https://edms.capenature.org.za/OTCS/cs.exe/ | keep template |
| `utils/nuclei/templates/discover/application/filetransferapplication/solarwinds-serv-u.yaml` | >=2 | https://51.222.110.72:443 | keep template |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/advantech-webaccess-scada.yaml` | 2/12 | http://153.142.33.8:80/broadWeb/bwRoot.asp?username=admin | keep template |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/aveva-edge.yaml` | >=1 | http://68.204.141.156:8080 | keep template |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/codesys-webvisu.yaml` | 4/12 | http://62.100.148.187:8080 | keep template |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/ge-proficy-webspace.yaml` | 5/12 | http://213.147.102.156:491 | keep template |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/iconics-mobilehmi.yaml` | >=1 | https://98.66.249.54:443/MobileHMI/ | keep template |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/inductive-automation-ignition-gateway.yaml` | 8/8 | http://47.250.157.145:3689/system/gwinfo | keep template |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/schneider-modicon-web.yaml` | >=1 | http://147.182.234.54:80 | keep template |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/siemens-simatic-hmi-web.yaml` | 8/12 | http://91.182.72.61:8080 | keep template |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/siemens-simatic-wincc.yaml` | >=4 | http://212.62.96.67:80 | keep template |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/tridium-niagara-bms-console.yaml` | >=2 | http://23.239.4.55:80 | keep template |
| `utils/nuclei/templates/discover/application/networkedgeapplication/check-point-mobile-access.yaml` | >=5 | https://112.175.151.212:443/sslvpn/Login/Login | keep template |
| `utils/nuclei/templates/discover/application/networkedgeapplication/cisco-asa-webvpn.yaml` | >=5 | http://89.167.72.144:3541/+CSCOE+/logon.html | keep template |
| `utils/nuclei/templates/discover/application/networkedgeapplication/citrix-gateway-edge.yaml` | >=4 | https://129.255.97.11:443/logon/LogonPoint/index.html | keep template |
| `utils/nuclei/templates/discover/application/networkedgeapplication/fortinet-fortigate-sslvpn.yaml` | 9/12 | http://3.137.185.136:80 | keep template |
| `utils/nuclei/templates/discover/application/networkedgeapplication/ivanti-connect-secure.yaml` | >=5 | http://13.112.188.95:8043 | keep template |
| `utils/nuclei/templates/discover/application/networkedgeapplication/sonicwall-sma.yaml` | >=5 | https://168.93.175.91:8443/login.action;jsessionid=node01eh0h23bsgkg8g2ndrq9s5xq515596.node0 | keep template |
| `utils/nuclei/templates/discover/application/networkedgeapplication/zscaler-private-access.yaml` | >=4 | http://165.155.150.245:80 | keep template |
| `utils/nuclei/templates/discover/application/networkmanagementsystem/aruba-instant.yaml` | 12/12 | http://108.253.173.43:8080 | keep template |
| `utils/nuclei/templates/discover/application/networkmanagementsystem/asuswrt-router-web-ui.yaml` | 1/12 | http://16.174.30.70:49686/chat | keep template |
| `utils/nuclei/templates/discover/application/networkmanagementsystem/cisco-ios-xe-web-ui.yaml` | >=1 | https://130.110.110.65:443 | keep template |
| `utils/nuclei/templates/discover/application/networkmanagementsystem/draytek-vigor-web-ui.yaml` | >=5 | https://185.93.27.59:444/weblogin.htm | keep template |
| `utils/nuclei/templates/discover/application/networkmanagementsystem/juniper-jweb.yaml` | >=4 | https://115.244.255.86:443 | keep template |
| `utils/nuclei/templates/discover/application/networkmanagementsystem/mikrotik-routeros-webfig.yaml` | >=3 | http://45.226.207.110:8090/webfig/ | keep template |
| `utils/nuclei/templates/discover/application/networkmanagementsystem/ruckus-wireless-management.yaml` | 12/12 | https://177.92.82.99:2376/admin/login.jsp | keep template |
| `utils/nuclei/templates/discover/application/networkmanagementsystem/tp-link-omada-controller.yaml` | >=1 | http://82.96.173.139:8080 | keep template |
| `utils/nuclei/templates/discover/application/outofbandapplication/generic-redfish.yaml` | >=5 | http://1.94.132.43:3098/redfish/v1/ | keep template |
| `utils/nuclei/templates/discover/application/secretmanagementapplication/vault.yaml` | >=5 | http://195.154.75.231:8200/v1/sys/health | keep template |
| `utils/nuclei/templates/discover/application/vdiapplication/apache-guacamole.yaml` | >=2 | http://216.158.238.125:8080 | keep template |
| `utils/nuclei/templates/discover/application/vdiapplication/citrix-storefront.yaml` | >=2 | https://206.210.162.128:443 | keep template |

## Noisy Shodan Candidates, No Live TP (1)

| Template | Live matches | Example/evidence | Action |
|---|---:|---|---|
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/siemens-wincc-unified.yaml` | 0/12 | 12 candidates inspected; fetched titles were unrelated products such as Netcore, AVAYA, ZyWALL, Ivanti, GlobalProtect, WordPress, and PaperCut. Treat as Shodan noise/no live TP, not a proven template failure. | needs real target or vendor fixture; do not loosen matcher based on noisy Shodan hits |

## Shodan Gap, No Live TP (23)

| Template | Live matches | Example/evidence | Action |
|---|---:|---|---|
| `utils/nuclei/templates/discover/application/filetransferapplication/goanywhere-mft.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
| `utils/nuclei/templates/discover/application/filetransferapplication/progress-wsftp.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/aveva-intouch-access-anywhere.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/aveva-plant-scada.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/ge-proficy-cimplicity.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/ge-proficy-ifix.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/iconics-genesis64.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/iconics-hyper-historian.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/mitsubishi-mc-works64.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/rockwell-factorytalk-services-platform.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/rockwell-factorytalk-view-se.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/rockwell-factorytalk-viewpoint.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/schneider-power-monitoring-expert.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/schneider-power-operation.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/siemens-pcs7-web.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
| `utils/nuclei/templates/discover/application/industrialcontrolsystem/wonderware-system-platform-web.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
| `utils/nuclei/templates/discover/application/networkedgeapplication/f5-bigip-apm.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
| `utils/nuclei/templates/discover/application/networkedgeapplication/palo-alto-globalprotect.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
| `utils/nuclei/templates/discover/application/networkmanagementsystem/dlink-router-web-ui.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
| `utils/nuclei/templates/discover/application/networkmanagementsystem/netgear-network-management.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
| `utils/nuclei/templates/discover/application/networkmanagementsystem/tenda-router-web-ui.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
| `utils/nuclei/templates/discover/application/networkmanagementsystem/totolink-router-web-ui.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
| `utils/nuclei/templates/discover/application/networkmanagementsystem/ubiquiti-unifi-network.yaml` | 0 | Shodan did not return usable candidates for the generated queries. This is not evidence that the template is bad. | needs stronger query, vendor fixture, or known deployment to prove TP |
