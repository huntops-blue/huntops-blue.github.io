Running blog of finding evil with [RockNSM](https://rocknsm.io).  

This blog is highlight the methodologies for threat hunting ("thrunting") through network data. These are malicious PCAPs, so it's a bit like hunting for a needle in a needle stack, but these processes work for small samples to very very large ones.  

Each blog post will start after using the [replaying packets](https://github.com/huntops-blue/huntops-blue.github.io/blob/master/rock-install.md#getting-data-into-rock) process with the linked packets per post.

RockNSM is an open source network security monitoring platform built with Zeek for protocol analysis, Suricata as an Intrusion Detection System (IDS), and the Elastic Stack for enrichment, storage, and visualization of network security data.  

- [ROCK installation guide](./rock-install.md)
- [Docket (the "Query PCAP" @dcode added to Kibana)](https://docs.rocknsm.io/services/docket/)
- [Replaying Packets](https://github.com/huntops-blue/huntops-blue.github.io/blob/master/rock-install.md#getting-data-into-rock)
- [Twitter @andythevariable](https://twitter.com/andythevariable)

# 2/24/2020 - Ursnif
- [Packets](http://malware-traffic-analysis.net/2020/02/11/index.html)
- [Ursnif banking trojan background](https://attack.mitre.org/software/S0386/)

Suricata has picked up some easy things to get started on, so let's start there.

![](./images/2-24-20-1.png)

Of particular interest to me (not that the others aren't interesting), are the executable signatures; so let's filter out the `opendns[.]com` lookups for now. This takes us down to a single source and destination to focus on, `194[.]61[.]2[.]16` and `10.2.11.101`.

![](./images/2-24-20-2.png)

Hopping over to the Discover tab, when we apply the source IP from the previous step, we see only 8 events...definitely manageable. Let's get rid of the `alert` dataset because we know about those from the Suricata dashboard.

![](./images/2-24-20-3.png)

Now that we've used the metadata to get down to a single IP address as the potential bad actor, let's use Docket to carve the packets for that IP and see what it can tell us. Using Wireshark on these packets, we follow the TCP stream and see this URL and a downloaded PE executable.

![](./images/2-24-20-4.png)

Exporting the HTTP object gives us the PE file, which we can analyze as well.

![](./images/2-24-20-5.png)

Using `exiftool`, we can see some interesting info, mainly that the original file was called `soldier.dll` and that the File Type is `Win32 EXE` (truncated).
```
$ exiftool lastimg.png
...
File Name                       : 215z9urlgz.php%3fl=xubiz8.cab
File Type                       : Win32 EXE
File Type Extension             : exe
MIME Type                       : application/octet-stream
Image File Characteristics      : Executable, 32-bit
PE Type                         : PE32
Original File Name              : soldier.dll
...
```

Checking with VirusTotal, we see that the file hash is [known bad](https://www.virustotal.com/gui/file/996fcd8c55f923e86477d3d8069f9e9b56c6301cf9b2678c5c5c40bf6a636a5f/detection) so this looks like a good find!

Now that we have a few more hints to search through, specifically `qr12s8ygy1[.]com`, let's go back to Kibana and remove the stuff we've already found and see if we can find anything else.

*Of note, `settings-win.data.microsoft.com` appears to be a Microsoft botnet sinkhole, so while we can use some of the info, I'm going to remove this from our searches to eliminate traffic routes to chase. Additionally, I'm filtering out the OpenDNS traffic.*

Moving along, let's make a Kibana data table to clean up our view a bit and we see `95[.]169[.]181[.]35` and `lcdixieeoe[.]com`, of note are those long URI's + an AVI file. Let's use Docket to see what's in those packets.

![](./images/2-24-20-6.png)

Hopping right into Exporting the HTTP objects, we see the `*.avi` files we observed in Kibana's `url.original` field. Let's save those and take a look.

![](./images/2-24-20-7.png)

In looking at the metadata for those "avi" files, we see that they're actually just Text files.

```
======== B.avi
...
File Name                       : B.avi
File Type                       : TXT
File Type Extension             : txt
MIME Type                       : text/plain
...
======== alSLK.avi
...
File Name                       : alSLK.avi
File Type                       : TXT
File Type Extension             : txt
MIME Type                       : text/plain
...
======== jNjcj.avi
...
File Name                       : jNjcj.avi
File Type                       : TXT
File Type Extension             : txt
MIME Type                       : text/plain
...
```

I poked and prodded on these files, but I'm not sure what they are...but I know they aren't normal media files. It looks like Base64 encoding, but I'm not sure what order they're supposed to be assembled in to decode. Either way, they have the `.avi` file extension and certainly aren't, so I'd put that in the suspect category.

Extract of `B.avi`
```
...
p1kTy18hM3gcANzilINMVJWdUP4AbxDka8IVGBACN+HkZxzdIOi86DoUwglmVgw+BsGdGC3WLgE45BoaeDFcYxpoS8/HzXcwtxxa45Wiqordymiv5JlqzxHWS647gV2B0XpV1+A5h9PTPvxdfJV/CIAYGgCqFLzlxXF3znojgEGWHj/MwRbhIgMIKm9FDqEQEqxjDIv0SC+sqN9TxpQLNPCdqJwMTuQN2sfat464J1bh9LWzHwPwyZXErBH5+XmvEbIjOX3ptyRJOa4C+W0Cf6yOFLIPWas659a0x5tZAQs1VbwMjylWLlx6LA2Dmop1C4dwb+zH5SSJrYo5RKbc6DV1AmmRpeJ1NXkO30Z2Bq27U+h3uRUnMulPWSp1uTeLwc8LSFK49kTIaV0lwWNfDeb975aPmPac6kZP/5g5xgfB5/53/kC2KvHCbMUF8RotemD2ak+Lc0gzP7W/pcmbw/ZhxmdFJd5rPJz1lhGIOEZX6buFkcg3vjsBInd319vLO+ZSZmbU8m1ZryNsfLZ56tEvbafgCY1Jz/tP4UdKL6DZPyjCXC7oIEoCO3yn/yHOaFFQvOFizv2OnUPVW3ST+BN/TwkHUSZfE1+lKvjXJBsONeaiAa5ozLa2uI/ebx1caPFMjw0j62H23r0YFd0opsTw2ovlkvKcx3eoT
...
```

Extract of a normal .avi files
```
RIFF,O
AVI LIST�hdrlavih85�
                    �"�LISTtstrlstrh8vidscvid�"�strf((�IV41JUNKLIST�;
movi00db~
���|
��`��؝����@�|��@�P!����9���&��y��i��y���y��y>�����<��<��y���<��<��<��<��<��<��<��<��<��<��<��<��<��<��<��<��<��<ϲ<����<��<��<ϳ��<��<��<��(��<��<��,��<�S<��<��<��|��y��y>���<��<��<����|n��y��y���y>3��y��y��y�Qm<�� �Z�;d�����ߢS%����T��!~nV�&~RVG���(p&
                                                                    ��۹+��$g�E���V���
�q��b�Z0���I.B�k����X�+|dy:$�X1��9��'ҙ*�
9�1d!��P�x����l�y"d�m'a��#Ԏ&Z]�"�%����fzڬ��q"j�g�c�X�(�p��j��xs`�<Ĺg�R�$��pY�1�
(
 p6��� E	s	V�pɫ�Œ�vNaG�(q�9�����"*���%
                                                    
                                                     �k�8mY��f�."s�8
                                                                    �(WL�!<-|=_���C&�ďo�s8��nj��T	sh��YX�oB�B��(NᠱI��ib��8���Y\�'1A�.�B$t´pHfB<�9���A�n5Hf�R�D��
                                                                                                                                                                      �g��9sVI���CsF!����2����S�Q�E�P��5Xj�txMF:�G�q�S��k�0N(3q]-��O�J��$��ID>��a�
����c'                                                      A9��
P@X
```

Trying a bit more on these files, 2 of these "avi" files end in `=` (`B.avi` and `jNjcj.avi`), so I am definitely leaning more towards Base64. The file that doesn't end in a `=` (`alSLK.avi`), I tried to append that to the top of the two files that do end in `=` and then run `base64 -D -i [file] -o [file]`, it created binary files (which seems like progress), but no luck in taking it apart. If anyone has any ideas here, feel free to reach out.

Malware Traffic Analysis noted another indicator that was identified through the analysis of the infected Word documents (`45[.]141[.]103[.]204` and `q68jaydon3t[.]com`), which we don't have. So while we see the traffic, it is all over TLS minus the initial DNS request so there's not much we can do for that. I'm adding it to the artifacts below, but this would only be "known bad" if it was found through analysis of the document.

## Artifacts
```
194[.]61[.]2[.]16
95[.]169[.]181[.]35
45[.]141[.]103[.]204 (found by Malware Traffic Analysis)
8962cd86b47148840b6067c971ada128
7e34d6e790707bcc862fd54c0129abfa
40186e831cd2e9679ca725064d2ab0fb
2b93fcafabab58a109fcbca4377cccda
qr12s8ygy1[.]com
lcdixieeoe[.]com
q68jaydon3t[.]com (found by Malware Traffic Analysis)
xubiz8[.]cab
/khogpfyc8n/215z9urlgz[.]php
```

Until next time, cheers and happy hunting!

# 2/21/2020 - Trickbot gtag wecan23 Infection
- [Packets](https://www.malware-traffic-analysis.net/2020/02/19/index.html)
- [Trickbot information stealer background](https://unit42.paloaltonetworks.com/trickbot-campaign-uses-fake-payroll-emails-to-conduct-phishing-attacks/)
- [gtag information stealer background](https://www.fireeye.com/blog/threat-research/2019/01/a-nasty-trick-from-credential-theft-malware-to-business-disruption.html)

Right out of the gate, the Suricata dashboard is telling us something is amiss.  

![](./images/2-20-20-1.png)

Let's pop over to the Discover tab and see what we can ferret out. We'll apply the `alert.signature exists` filter and add `destination.ip`, `source.ip`, `alert.signature`, and `alert.metadata.tag` and, pretty maids, all in a row.

| Destination IP  | Source IP    | Signature                                                      | Tag            |
|-----------------|--------------|----------------------------------------------------------------|----------------|
| 195[.]123[.]220[.]154 | 10.0.100.185 | ET CNC Feodo Tracker Reported CnC Server group 12        | Banking_Trojan |
| 185[.]65[.]202[.]240  | 10.0.100.185 | ET CNC Feodo Tracker Reported CnC Server group 8         | Banking_Trojan |
| 190[.]214[.]13[.]2    | 10.0.100.185 | ET CNC Feodo Tracker Reported CnC Server group 11        | Banking_Trojan |
| 104[.]20[.]16[.]242   | 10.0.100.185 | ET POLICY curl User-Agent Outbound                       | -              |
| 104[.]20[.]16[.]242   | 10.0.100.185 | ET POLICY IP Check Domain (icanhazip[.]com in HTTP Host) | -              |

Boom, we found the Trickbot TLS connections, but what about `wecan23`?

*Note: As I dug through this, I found a lot of DNS traffic to blocklists (`cbl.abuseat[.]org`, `barracudacentral[.]org`, `uceprotect[.]net`, etc.). While the victim (or the pcap sampler) seemingly use these lists, I excluded this as it's not part of the infection.*

As we see in the the table above, `10.0.100.185` seems to be infected. So let's filter in on that IP address in Kibana.

![](./images/2-20-20-2.png)

Let's get rid of our known bad Destination IPs (above), the IP recon domains (`icanhazip` and `externalip.com`), and see what is left over to see if there's anything else we can find. I'm also going to drop the DNS server out (`10.0.100.2`), while there's good info there, we've got others to look at that might have more. If there's nothing, we can do a DNS hunt.

![](./images/2-20-20-3.png)

Of interest, the connection between `10.0.100.185` and `192[.]3[.]124[.]40` is over port `80`, but there's not a corresponding HTTP Zeek log, so we'll have to use Docket to carve the PCAP and check it out in Wireshark.

![](./images/2-20-20-4.png)

As we can see, the file name is `lastimg.png`, but the file type metadata has a magic number of `MZ`, which is a PE binary. Using `Export HTTP Objects` in Wireshark, we can see there are 2 "png" files called `lastimg.png` as well as `mini.png`. We'll carve those out and statically analyze them.

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

Let's see what VirusTotal knows about these 2 files by searching their MD5 hashes [1](https://www.virustotal.com/gui/search/489eef73a1a5880f644f3b60267db7e8)[2](https://www.virustotal.com/gui/search/c1820b0685ea2c16a9da3efd2f3b58d9)...**EVIL!**.

Back to Kibana and see what else is there. As before, let's get rid of our known bad and all we have left is `203[.]176[.]135[.]102`.

![](./images/2-20-20-5.png)

Like before, it's only Connection log stuff, so let's carve the PCAP between `10.0.100.185` and `203[.]176[.]135[.]102` and see what we find in Wireshark, which appears to be posting host IDs, running processes, usernames, workstation domain, etc. to a server `Cowboy`.

![](./images/2-20-20-6.png)

There was a lot of this kind of data being uploaded; feel free to explore it on your own and...obfuscating all of this data is exhausting.

## Artifacts
```
203[.]176[.]135[.]102
195[.]123[.]220[.]154
185[.]65[.]202[.]240
190[.]214[.]13[.]2
192[.]3[.]124[.]40
/wecan23/
489eef73a1a5880f644f3b60267db7e
c1820b0685ea2c16a9da3efd2f3b58d9
```

Until next time, cheers and happy hunting!

---
*Packets provided by [Malware Traffic Analysis](https://www.malware-traffic-analysis.net) - @malware_traffic*
