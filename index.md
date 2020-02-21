Running blog of finding evil with [RockNSM](https://rocknsm.io).

RockNSM is an open source network security monitoring platform built with Zeek for protocol analysis, Suricata as an Intrusion Detection System (IDS), and the Elastic Stack for enrichment, storage, and visualization of network security data.

- [ROCK installation guide](./rock-install.md)
- [Replaying Packets](https://github.com/huntops-blue/huntops-blue.github.io/blob/master/rock-install.md#getting-data-into-rock)

# Trickbot gtag wecan23 Infection
- [Packets](https://www.malware-traffic-analysis.net/2020/02/19/index.html)
- [Trickbot information stealer background](https://unit42.paloaltonetworks.com/trickbot-campaign-uses-fake-payroll-emails-to-conduct-phishing-attacks/)
- [gtag information stealer background](https://www.fireeye.com/blog/threat-research/2019/01/a-nasty-trick-from-credential-theft-malware-to-business-disruption.html)

Right out of the gate, the Suricata dashboard is telling us something is amiss.  
![](./images/2-20-20-1.png)

Let's pop over to the Discover tab and see what we can ferret out. We'll apply the `alert.signature exists` filter and add `destination.ip`, `source.ip`, `alert.signature`, and `alert.metadata.tag` and, pretty maids, all in a row.

| Destination IP  | Source IP    | Signature                                         | Tag            |
|-----------------|--------------|---------------------------------------------------|----------------|
| 195.123.220.154 | 10.0.100.185 | ET CNC Feodo Tracker Reported CnC Server group 12 | Banking_Trojan |
| 185.65.202.240  | 10.0.100.185 | ET CNC Feodo Tracker Reported CnC Server group 8  | Banking_Trojan |
| 190.214.13.2    | 10.0.100.185 | ET CNC Feodo Tracker Reported CnC Server group 11 | Banking_Trojan |

Boom, we found the Trickbot TLS connections, but what about `wecan23`?

---
*Packets provided by [Malware Traffic Analysis](https://www.malware-traffic-analysis.net) - @malware_traffic*
