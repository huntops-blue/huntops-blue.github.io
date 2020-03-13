---
layout: default
---

Running blog of finding evil with [RockNSM](https://rocknsm.io).  

This blog is highlight the methodologies for threat hunting ("thrunting") through network data. These are malicious PCAPs, so it's a bit like hunting for a needle in a needle stack, but these processes work for small samples to very very large ones. That said, I'm not going to "find" things that could only be identified if you knew what you were looking for. If I can find it, we'll showcase it, but if the C2 (as an example) looks like legitimate traffic, we'll list it as an artifact, but I'm not going to pretend that every packet observed is bad if I can't prove it.

Each blog post will start after using the [replaying packets](https://github.com/huntops-blue/huntops-blue.github.io/blob/master/rock-install.md#getting-data-into-rock) process with the linked packets per post.

RockNSM is an open source network security monitoring platform built with Zeek for protocol analysis, Suricata as an Intrusion Detection System (IDS), and the Elastic Stack for enrichment, storage, and visualization of network security data.  

- [ROCK installation guide](./rock-install.md)
- [Docket (the "Query PCAP" @dcode added to Kibana)](https://docs.rocknsm.io/services/docket/)
- [Replaying Packets](https://github.com/huntops-blue/huntops-blue.github.io/blob/master/rock-install.md#getting-data-into-rock)
- [Twitter @andythevariable](https://twitter.com/andythevariable)

---

<ul>
  {% for post in site.posts %}
    <li>
      <a href="{{ post.url }}">{{ post.title }}</a>
    </li>
  {% endfor %}
</ul>

---

*Packets provided by [Malware Traffic Analysis](https://www.malware-traffic-analysis.net) - @malware_traffic*
