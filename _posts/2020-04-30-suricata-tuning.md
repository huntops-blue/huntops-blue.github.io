---
layout: default
title: "4/30/2020 - Tuning Suricata"
tags: feed
---
# 4/30/2020 - Tuning Suricata
No packets to share this time as this was from a real hunt op.

I had a bit of a scare around a RAT and wanted to walk through the tuning process because I think it's a task for thrunters...if it *should* be a task for us is another story.

![](/images/thrunting-detection-engineering.png)

First off, you can see where some tuning has been done in the identification of network noise, this is part of the process when doing IR - identifying false positives and network weirdness/oddities.

![](/images/4-30-20-1.png)

After some wide swath tuning, we had some hits for some Emerging Threats rules, which is more interesting. Of specific note, that I spent some time on, was `ET TROJAN Backdoor family PCRat/Gh0st CnC traffic` and it was quite an exciting dance.

![](/images/4-30-20-2.png)

After seeing the hit on the Suricata dashboard, I applied it as a filter by clicking on the `+` and then saw that we were looking at 8 source IPs. That was instantly more interesting in that it wasn't the whole network hitting this signature. Also of note was that it was port `135` (which became helpful later).

![](/images/4-30-20-3.png)

In digging in a bit more, I hopped over to Discover to see what was happening around the alert. There was NTLM authentication, the alert, and then DCE_RPC traffic. I focused on a single IP to start and then looked at the other 8 to see if the traffic was the same, and it was.

![](/images/4-30-20-4.png)

So, next I wanted to check the Suricata rule to see what exactly what happening. Expanding the event in Kibana showed me that the `rule.id` field was `2016922`. So let's look at that rule on the sensor to see what's going on.

With [dcode](https://twitter.com/dcode)'s help, we can see that it's looking for the content `78 9c` (among other things).

```
grep 2016922 /var/lib/suricata/rules/suricata.rules

alert tcp $HOME_NET !80 -> $EXTERNAL_NET [!5721,!5938] (msg:"ET TROJAN Backdoor family PCRat/Gh0st CnC traffic"; flow:to_server,established; dsize:>11; content:"|78 9c|"; offset:8; byte_jump:4,-10,relative,little,from_beginning,post_offset -1; isdataat:!2,relative; content:!"PWHDR"; depth:5; metadata: former_category MALWARE; reference:url,www.securelist.com/en/descriptions/10155706/Trojan-GameThief.Win32.Magania.eogz; reference:url,www.microsoft.com/security/portal/Threat/Encyclopedia/Entry.aspx?Name=Backdoor%3AWin32%2FPcClient.ZR&ThreatID=-2147325231; reference:url,labs.alienvault.com/labs/index.php/2012/new-macontrol-variant-targeting-uyghur-users-the-windows-version-using-gh0st-rat/; reference:url,www.infowar-monitor.net/2009/09/tracking-ghostnet-investigating-a-cyber-espionage-network/; reference:url,blogs.rsa.com/will-gragido/lions-at-the-watering-hole-the-voho-affair/; reference:url,www.norman.com/about_norman/press_center/news_archive/2012/the_many_faces_of_gh0st_rat/en; classtype:trojan-activity; sid:2016922; rev:14; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag PCRAT, tag Gh0st, tag RAT, signature_severity Critical, created_at 2013_04_23, malware_family Gh0st, malware_family PCRAT, updated_at 2019_08_06;)
```

Okay, now we know what the signature is looking for, lets see what caused it to trip by carving the PCAP with Docket (the `Query PCAP` field in ROCK) and analyzing it in Wireshark.

Searching for the content we identified in the rule (`78 9c`) we can now see what's causing the hit. `789c` is in the New Technology Local Area Network Manager Security Support Provider (NTLMSSP) Verifier Body! NTLM is a suite of protocols used by Microsoft to provide authentication. It looks like the NTLMSSSP Verifier Body, which is a sequence of bytes, is causing the hit when `789c` shows up.

![](/images/4-30-20-5.png)

Phew...a false positive. Now what? Let's make some changes to the Suricata rule so we're not seeing it for NTLM.

We can make the change by creating a file called `modify.conf` in the `/etc/suricata` directory on ROCK. This will ensure that the changes persist through rule updates using `suricata-update`. The modify file works by defining the rule ID (sid), what it is currently and then what you want to change it to.

So the ports for the rule already state `!5721,!5938`, so let's change it to also exclude port `135`.

```
sudo vi /etc/suricata/modify.conf

# Add the following
# Changing ET TROJAN Backdoor family PCRat/Gh0st CnC traffic to not flag on NTLMSSP Verifier Body content
2016922 "!5721,!5938" "!5721,!5938,!135"
```
Let's apply the new rules with `suricata-update`.
```
sudo -u suricata -g suricata suricata-update
```

Next we can check to make sure that the rule worked with `grep 2016922 /var/lib/suricata/rules/suricata.rules` and we should see `!135` added (`$EXTERNAL_NET [!5721,!5938,!135]`).
```
alert tcp $HOME_NET !80 -> $EXTERNAL_NET [!5721,!5938,!135] (msg:"ET TROJAN Backdoor family PCRat/Gh0st CnC traffic"; flow:to_server,established; dsize:>11; content:"|78 9c|"; offset:8; byte_jump:4,-10,relative,little,from_beginning,post_offset -1; isdataat:!2,relative; content:!"PWHDR"; depth:5; metadata: former_category MALWARE; reference:url,www.securelist.com/en/descriptions/10155706/Trojan-GameThief.Win32.Magania.eogz; reference:url,www.microsoft.com/security/portal/Threat/Encyclopedia/Entry.aspx?Name=Backdoor%3AWin32%2FPcClient.ZR&ThreatID=-2147325231; reference:url,labs.alienvault.com/labs/index.php/2012/new-macontrol-variant-targeting-uyghur-users-the-windows-version-using-gh0st-rat/; reference:url,www.infowar-monitor.net/2009/09/tracking-ghostnet-investigating-a-cyber-espionage-network/; reference:url,blogs.rsa.com/will-gragido/lions-at-the-watering-hole-the-voho-affair/; reference:url,www.norman.com/about_norman/press_center/news_archive/2012/the_many_faces_of_gh0st_rat/en; classtype:trojan-activity; sid:2016922; rev:14; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag PCRAT, tag Gh0st, tag RAT, signature_severity Critical, created_at 2013_04_23, malware_family Gh0st, malware_family PCRAT, updated_at 2019_08_06;)
```
Restart Suricata (`sudo systemctl restart suricata`) to pick up the new rules and you're golden.

![](/images/hulk-rule-tuning.jpg)
