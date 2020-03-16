---
layout: default
title: "3/20/2020 - Hancitor w/Coronavirus Themed Malspam"
tags: feed
---
# 3/20/2020 - Hancitor Infection w/Coronavirus Themed Malspam
- [Packets](http://malware-traffic-analysis.net/2020/03/11/index.html)
- [Hancitor Downloader background (AKA Chanitor)](https://www.cyber.nj.gov/threat-profiles/trojan-variants/hancitor)

Unless you've been living under a rock, you're aware of the global COVID-19 pandemic, also known as Coronavirus...actually...even if you're under a rock, you're still likely aware. Adversaries commonly capitalize on these type of events for their malspam lures, [COVID is no difference](https://krebsonsecurity.com/2020/03/live-coronavirus-map-used-to-spread-malware/). If the bad guys are using this, as defenders, we need to be prepared. In this situation, malspam is used to distribute the Hancitor (Chanitor) downloader.

We'll start over on the Suricata dashboard to see if anything look suspicious, and as per normal, we have a hint of where to start with the `ET MALWARE Fareit/Pony Downloader Checkin 2` alert. As we commonly see with these infections, adversaries commonly do an external IP lookup to see where they are and/or to validate they've infected the right victim (for targeted intrusions); that said, remember that an external IP lookup, while interesting, isn't a smoking gun - so we'll put that in the evidence pile, but not "this == that".

![](/images/3-20-20-1.png)

Filtering on the Pony Downloader alert, we can see that `10.3.11.101` looks like the internal host as well as `45[.]153[.]73[.]33` as the, we'll call it C2 because the alert calls it `Downloader Checkin 2`, external host. Of note, this connection is over port `80`, so we should have good metadata to dig through. We'll also use the HTTP dashboard to see what it can tell us.

![](/images/3-20-20-2.png)

Before we move away from the Suricata dashboard, the alert is called Pony, which is part of the process that Hanciator uses to burrow into an infected system - usually Hancinator uses a VB macro to get Pony and then Pony acts as an installer to download the next stage (ransomware, banking trojan, etc.) [1](https://www.reddit.com/r/blackhat/comments/5oee1h/what_is_a_pony_downloader/), [2](https://www.proofpoint.com/us/threat-insight/post/hancitor-ruckguv-reappear), [3](https://www.fireeye.com/blog/threat-research/2016/09/hancitor_aka_chanit.html). Using that OSINT, we know that we're probably looking for a VB macro, which likely means an Office document.

Okay, lets pop on over to ROCK's HTTP dashboard and see what we can learn about `45[.]153[.]73[.]33`. Here when we apply the filter for our bad IP address, we can see the HOST (`thumbeks[.]com`) and the URI's...all PHP files (`/4/forum[.]php`, `/d2/about[.]php`, `/mlu/forum[.]php`). [PHP](https://www.php.net/) is a web-centric scripting language that is perfect for all kinds of useful applications...and malware.

![](/images/3-20-20-3.png)

Applying different filters to this dashboard shows that only `10.3.11.101` and `45[.]153[.]73[.]33` are the only two systems talking back and forth with `thumbeks[.]com`, so lets look in the Discover app to learn a bit more.

I've searched on the IP that we're interested in and applied the `http` dataset filter. Of note, I've added fields that I'm most interested in source IP, URL, etc. but I've also added the `Query PCAP` field so that I can use that to quickly carve the packets using Docket and Stenographer, both built into RockNSM. This traffic is over port 80 and likely unencrypted, so we should be able to get some good data from it.

I'll carve the PCAPs for `/4/forum[.]php`, `/d2/about[.]php`, and `/mlu/forum[.]php` to analyze them.

![](MALTEGO IMAGE)

## Detection Logic
[Additional analysis, modeling, and signatures (KQL and Yara)](https://github.com/huntops-blue/detection-logic/blob/master/trickbot.md).

## Artifacts
```
45[.]153[.]73[.]33 - Pony Downloader C2
/4/forum[.]php
/d2/about[.]php
/mlu/forum[.]php
```

Until next time, cheers and happy hunting!
