Running blog of finding evil with [RockNSM](https://rocknsm.io).

RockNSM is an open source network security monitoring platform built with Zeek for protocol analysis, Suricata as an Intrusion Detection System (IDS), and the Elastic Stack for enrichment, storage, and visualization of network security data.

- [ROCK installation guide](./rock-install.md)
- [Docket (the "Query PCAP" ROCK added to Kibana)](https://docs.rocknsm.io/services/docket/)
- [Replaying Packets](https://github.com/huntops-blue/huntops-blue.github.io/blob/master/rock-install.md#getting-data-into-rock)

# 2/21/2020 - Trickbot gtag wecan23 Infection
- [Packets](https://www.malware-traffic-analysis.net/2020/02/19/index.html)
- [Trickbot information stealer background](https://unit42.paloaltonetworks.com/trickbot-campaign-uses-fake-payroll-emails-to-conduct-phishing-attacks/)
- [gtag information stealer background](https://www.fireeye.com/blog/threat-research/2019/01/a-nasty-trick-from-credential-theft-malware-to-business-disruption.html)

Right out of the gate, the Suricata dashboard is telling us something is amiss.  

![](./images/2-20-20-1.png)

Let's pop over to the Discover tab and see what we can ferret out. We'll apply the `alert.signature exists` filter and add `destination.ip`, `source.ip`, `alert.signature`, and `alert.metadata.tag` and, pretty maids, all in a row.

| Destination IP  | Source IP    | Signature                                              | Tag            |
|-----------------|--------------|--------------------------------------------------------|----------------|
| 195[.]123[.]220[.]154 | 10.0.100.185 | ET CNC Feodo Tracker Reported CnC Server group 12      | Banking_Trojan |
| 185[.]65[.]202[.]240  | 10.0.100.185 | ET CNC Feodo Tracker Reported CnC Server group 8       | Banking_Trojan |
| 190[.]214[.]13[.]2    | 10.0.100.185 | ET CNC Feodo Tracker Reported CnC Server group 11      | Banking_Trojan |
| 104[.]20[.]16[.]242   | 10.0.100.185 | ET POLICY curl User-Agent Outbound                     | -              |
| 104[.]20[.]16[.]242   | 10.0.100.185 | ET POLICY IP Check Domain (icanhazip[.]com in HTTP Host)| -              |

Boom, we found the Trickbot TLS connections, but what about `wecan23`?

*Note: As I dug through this, I found a lot of DNS traffic to blocklists (`cbl.abuseat[.]org`, `barracudacentral[.]org`, `uceprotect[.]net`, etc.). While the victim (or the pcap sampler) seemingly use these lists, I excluded this as it's not part of the infection.*

As we see in the the table above, `10.0.100.185` seems to be infected. So let's filter in on that IP address in Kibana.

![](./images/2-20-20-2.png)

Let's get rid of our known bad Destination IPs (above), the IP recon domains (`icanhazip` and `externalip.com`), and see what is left over to see if there's anything else we can find. I'm also going to drop the DNS server out (`10.0.100.2`), while there's good info there, we've got others to look at that might have more. If there's nothing, we can do a DNS hunt.

![](./images/2-20-20-3.png)

Of interest, the connection between `10.0.100.185` and `192.3.124.40` is over port `80`, but there's not a corresponding HTTP Zeek log, so we'll have to use Docket to carve the PCAP and check it out in Wireshark.

![](./images/2-20-20-4.png)

As we can see, the file name is `lastimg.png`, but the file type metadata has a magic number of `MZ`, which is a PE binary. Using `Export HTTP Objects` in Wireshark, we can see there are **2** "png" files called `lastimg.png` as well as `mini.png`. We'll carve those out and statically analyze them.

Using `exiftool`, we can see some interesting info, mainly that the original file was called `002.exe` and that the File Type is `Win32 EXE`, not an image (truncated).
```
$ exiftool lastimg.png
...
File Name                       : lastimg.png
File Type                       : Win32 EXE
File Type Extension             : exe
MIME Type                       : application/octet-stream
Image File Characteristics      : Executable, 32-bit
PE Type                         : PE32
Original File Name              : 002.exe
Product Name                    : 002.exe
...
```

Let's see what VirusTotal knows about these 2 files by searching their MD5 hashes (`489eef73a1a5880f644f3b60267db7e8` and `c1820b0685ea2c16a9da3efd2f3b58d9`)...**EVIL!**.

Back to Kibana and see what else is there. As before, let's get rid of our known bad and all we have left is `203[.]176[.]135[.]102`.

![](./images/2-20-20-5.png)

Like before, it's only Connection log stuff, so let's carve the PCAP between `10.0.100.185` and `203[.]176[.]135[.]102` and see what we find in Wireshark, which appears to be posting host IDs, running processes, usernames, workstaion domain, etc. to a server `Cowboy`.

![](./images/2-20-20-6.png)

We'll stop here because obfuscating all of this data is exhausting. /cheers

---
*Packets provided by [Malware Traffic Analysis](https://www.malware-traffic-analysis.net) - @malware_traffic*
