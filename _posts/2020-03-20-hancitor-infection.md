---
layout: default
title: "3/20/2020 - Hancitor w/Coronavirus Themed Malspam"
tags: feed
---
# 3/20/2020 - Hancitor Infection w/Coronavirus Themed Malspam
- [Packets](http://malware-traffic-analysis.net/2020/03/11/index.html)
- [Hancitor Downloader background (AKA Chanitor)](https://www.cyber.nj.gov/threat-profiles/trojan-variants/hancitor)

Unless you've been living under a rock, you're aware of the global COVID-19 pandemic, also known as Coronavirus...actually...even if you're under a rock, you're still likely aware. Adversaries commonly capitalize on these type of events for their malspam lures, [COVID is no different](https://krebsonsecurity.com/2020/03/live-coronavirus-map-used-to-spread-malware/). If the bad guys are using this, as defenders, we need to be prepared. In this situation, malspam is used to distribute the Hancitor (Chanitor) downloader.

We'll start over on the Suricata dashboard to see if anything look suspicious, and as per normal, we have a hint of where to start with the `ET MALWARE Fareit/Pony Downloader Checkin 2` alert. As we commonly see with these infections, adversaries commonly do an external IP lookup to see where they are and/or to validate they've infected the right victim (for targeted intrusions); that said, remember that an external IP lookup, while interesting, isn't a smoking gun - so we'll put that in the evidence pile, but not "this == that".

![](/images/3-20-20-1.png)

Filtering on the Pony Downloader alert, we can see that `10.3.11.101` looks like the internal host as well as `45[.]153[.]73[.]33` as the, we'll call it C2 because the alert calls it `Downloader Checkin 2`, external host. Of note, this connection is over port `80`, so we should have good metadata to dig through. We'll also use the HTTP dashboard to see what it can tell us.

![](/images/3-20-20-2.png)

Before we move away from the Suricata dashboard, the alert is called Pony, which is part of the process that Hanciator uses to burrow into an infected system - usually Hancinator uses a VB macro to get Pony and then Pony acts as an installer to download the next stage (ransomware, banking trojan, etc.) [1](https://www.reddit.com/r/blackhat/comments/5oee1h/what_is_a_pony_downloader/), [2](https://www.proofpoint.com/us/threat-insight/post/hancitor-ruckguv-reappear), [3](https://www.fireeye.com/blog/threat-research/2016/09/hancitor_aka_chanit.html). Using that OSINT, we know that we're probably looking for a VB macro, which likely means an Office document.

Okay, lets pop on over to ROCK's HTTP dashboard and see what we can learn about `45[.]153[.]73[.]33`. Here when we apply the filter for our bad IP address, we can see the HOST (`thumbeks[.]com`) and the URI's...all PHP files (`/4/forum[.]php`, `/d2/about[.]php`, `/mlu/forum[.]php`). [PHP](https://www.php.net/) is a web-centric scripting language that is perfect for all kinds of useful applications...and malware.

![](/images/3-20-20-3.png)

Applying different filters to this dashboard shows that only `10.3.11.101` and `45[.]153[.]73[.]33` are the only two systems talking back and forth with `thumbeks[.]com`, so lets look in the Discover app to learn a bit more.

I've searched on the host that we're interested in and applied the `http` dataset filter. Of note, I've added fields that I'm most interested in source IP, URL, etc. but I've also added the `Query PCAP` field so that I can use that to quickly carve the packets using Docket and Stenographer, both built into RockNSM. This traffic is over port 80 and likely unencrypted, so we should be able to get some good data from it. Finally, we'll know more when we look at the HTTP headers, but the HTTP Method is a POST, so this is likely data exfil of some type.

![](/images/3-20-20-4.png)

I'll carve the PCAPs for `/4/forum[.]php`, `/d2/about[.]php`, and `/mlu/forum[.]php` to analyze them.

Right off the bat with the first `/4/forum[.]php`, we can see that this is uploading a GUID and build number of the implant along with the hostname (`[redacted]-WIN10`), the userID (`[redacted]-WIN10\[username]`) and the host IP address (`IP=[redacted]`) along with a Base64 encoded string
```
NMNMARZAEg4OCkBVVQkSFQpUGwgOGxwcExQTDg4fH1QZFRdVDQpXExQZFg8eHwlVCRUeEw8XJRkVFwobDlVLBhIODgpAVVUYHw4bVBsIDhscHBMUEw4OHx9UGRUXVQ0KVxMUGRYPHh8JVRwVFA4JVUsGEg4OCglAVVUJEwkJVBkVVBMUVUsGEg4OCkBVVRcTGQgVGBYbHhMUHREPFg8YD1QZFRdVSwYSDg4KQFVVCQ4VGREXGwgRHw4IHwwVFg8OExUUVBkVF1VLBwEYQBIODgpAVVUJEhUKVBsIDhscHBMUEw4OHx9UGRUXVQ0KVxMUGRYPHh8JVQkVHhMPFyUZFRcKGw5VSAYSDg4KQFVVGB8OG1QbCA4bHBwTFBMODh8fVBkVF1UNClcTFBkWDx4fCVUcFRQOCVVIBhIODgoJQFVVCRMJCVQZFVQTFFVIBhIODgpAVVUXExkIFRgWGx4TFB0RDxYPGA9UGRUXVUgGEg4OCkBVVQkOFRkRFxsIER8OCB8MFRYPDhMVFFQZFRdVSAc=
```
This is followed by posting binary files from `/d2/about[.]php` and `/mlu/forum[.]php`

![](/images/3-20-20-5.png)
![](/images/3-20-20-6.png)
![](/images/3-20-20-7.png)

After the initial `/4/forum[.]php` + `/d2/about[.]php` + `/mlu/forum[.]php`, there are 3 more POSTs to `/4/forum[.]php` which have 2 different Base64 encoded strings (`CMNXARRABw==` and `AZAZARRABw==`). In checking online for those strings, there was 1 link to [Hybrid-Analysis](https://www.hybrid-analysis.com/sample/fdbc89d95c002985f71ef3a8471bded05e71559874f36dd12186def8eef73e81?environmentId=100) for a Hancitor analysis from 2018 (we knew this was Hancitor already, but this is the first evidence pointing us that direction).

So, let's remove `thumbeks[.]com`, `/4/forum[.]php`, `/d2/about[.]php`, and `/mlu/forum[.]php` and move onto other suspicious traffic.

When looking at the remaining traffic, it became pretty obvious that there was more that I could just sift through the Discover app and honestly say I found bad traffic. So, let's focus on DNS, use a data table visualization, and remove the IP lookup API (`api.ipify.org` and `thumbeks[.]com`...ah, 2 entries and we now have 4 additional indicators to research to see if they are bad (2 hosts, 2 IPs)

![](/images/3-20-20-8.png)

Lets start with the hosts (`freetospeak[.]me` and `shop[.]artaffinittee[.]com`) and see what else we know about them. Right off the bat, looking at the DNS, domains, and files, we can see that there is a file located at `freetospeak[.]me/0843_43[.]php`, but the filename is `SE-670131329809_5500[.]zip`.

![](/images/3-20-20-9.png)

We'll grab the packets to see what's there, but in doing a quick Google search for `0843_43.php` I can see that [Abuse.ch](https://urlhaus.abuse.ch/url/323970/) has listed some of the payloads that are delivered from this URI and they follow what we've observed - two capital letters, a dash, 12 numbers, and underscore, 4 numbers, and a zip file extension. We'll have a regex search in the Detection Logic section, but lets check out the packets.

![](/images/3-20-20-10.png)

Lets use the Export HTTP Object of Wireshark to grab that file so we can do some additional analysis. Running the file command, we see that this isn't a PHP file, but a zip archive (we assumed that based on the file.name field in ROCK, but that's why we check).

```
/usr/bin/file 0843_43.php
0843_43.php: Zip archive data, at least v2.0 to extract
```

Great, let's grab some metadata about the file with `exiftool`.

```
/usr/local/bin/exiftool 0843_43.php
ExifTool Version Number         : 11.85
File Name                       : 0843_43.php
Directory                       : .
File Size                       : 225 kB
File Modification Date/Time     : 2020:03:16 16:04:34-05:00
File Access Date/Time           : 2020:03:16 16:04:48-05:00
File Inode Change Date/Time     : 2020:03:16 16:04:53-05:00
File Permissions                : rw-r--r--
File Type                       : ZIP
File Type Extension             : zip
MIME Type                       : application/zip
Zip Required Version            : 20
Zip Bit Flag                    : 0
Zip Compression                 : Deflated
Zip Modify Date                 : 2020:03:10 19:22:42
Zip CRC                         : 0x8780657b
Zip Compressed Size             : 230297
Zip Uncompressed Size           : 1130515
Zip File Name                   : SE670131329809.vbs
```
We can see that the `Zip File Name` has `SE670131329809.vbs`. Interesting! Let's list the contents of the zip file and see if there's anything else interesting in there.
```
/usr/bin/unzip -l 0843_43.php
Archive:  0843_43.php
  Length      Date    Time    Name
---------  ---------- -----   ----
  1130515  03-10-2020 19:22   SE670131329809.vbs
---------                     -------
  1130515                     1 file
```
We can see that the archive was created on March 10, 2020 and that there is one file in there (`SE670131329809.vbs`). Let's unzip and poke around on the file.
```
/usr/bin/unzip -K 0843_43.php
Archive:  0843_43.php
  inflating: SE670131329809.vbs
```
Now, let's grab the hash of this script and see if anyone else has already done the hard work.
```
/sbin/md5 SE670131329809.vbs
MD5 (SE670131329809.vbs) = 8eb933c84e7777c7b623f19489a59a2a
```
As it would turn out, it looks like someone has already submitted this to [VirusTotal](https://www.virustotal.com/gui/file/6897a3b85046ba97fb3868dfb82338e5ed098136720a6cf73625e784fc1e1e51/detection) and its got a 20/59 score, so this looks like a good hit! As we continue to look at the [behavior](https://www.virustotal.com/gui/file/6897a3b85046ba97fb3868dfb82338e5ed098136720a6cf73625e784fc1e1e51/behavior/Lastline) of this file, it looks like it's responsible for our connections to `thumbeks[.]com` and `api[.]ipify[.]org` (this is great because now we have a real reason to look at IPIFY, whereas before it was just suspicious, but now we can connect it to malware, so we can dig into that more), and a new domain (`cludions[.]com` - but we don't have any traffic to that domain in our sample). Of note, VT has some neat node analysis of this sample [here](https://www.virustotal.com/graph/6897a3b85046ba97fb3868dfb82338e5ed098136720a6cf73625e784fc1e1e51).

![](MALTEGO IMAGE)

## Detection Logic
[Additional analysis, modeling, and signatures (KQL and Yara)](https://github.com/huntops-blue/detection-logic/blob/master/trickbot.md).

`[A-Za-z]{2}-[0-9]{12}_[0-9]{4}.zip` <- Andy, this is for SE-670131329809_5500[.]zip

## Artifacts
```
45[.]153[.]73[.]33 - Pony Downloader C2
/4/forum[.]php - Hancitor C2
/d2/about[.]php - Hancitor C2
/mlu/forum[.]php - Hancitor C2
freetospeak[.]me
shop[.]artaffinittee[.]com
8eb933c84e7777c7b623f19489a59a2a - VBScript dropper
```

Until next time, cheers and happy hunting!
