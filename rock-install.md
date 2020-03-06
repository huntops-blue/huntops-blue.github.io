# Installing RockNSM
This isn't a full walkthrough, it's meant to be a quick and dirty quick-start.

If you already have ROCK installed and just need to understand getting test data in, skip to [the end](https://github.com/huntops-blue/huntops-blue.github.io/blob/master/rock-install.md#getting-data-into-rock).

# Preparation
Do this to get started.
1. Download the latest [ROCK ISO](https://download.rocknsm.io/isos/stable/)
1. Download a hypervisor (I'll walk through VMWare Fusion and VirtualBox, but there are many options)
 - [VMWare Fusion](https://www.vmware.com/products/fusion/fusion-evaluation.html) (paid) **or** [VirtualBox](https://www.virtualbox.org/wiki/Downloads) (free)

# Installation
Select the right hypervisor you're using.

- [VMWare Fusion](https://github.com/huntops-blue/huntops-blue.github.io/blob/master/rock-install.md#vmware-fusion-installation-instructions)
- [VirtualBox](https://github.com/huntops-blue/huntops-blue.github.io/blob/master/rock-install.md#virtualbox-installation-instructions)

## VMWare Fusion Installation Instructions
If you're using VirtualBox, go to those [instructions](https://github.com/huntops-blue/huntops-blue.github.io/blob/master/rock-install.md#virtualbox-installation-instructions)

1. Install VMWare Fusion
1. Create a New virtual Machine
1. Select Install from disc or image
1. Select the ROCK ISO you downloaded
1. Select Legacy BIOS or UEFI (it doesn't really matter for this)
1. Click "Customize Settings"
1. Click on "Processors & Memory", set 4 processor cores and `12288` MB
1. Click on "Add Device", add another Network Adapter
1. Click on "Hard Disk", move it to `50.00` GB or more
1. Move onto [deploying ROCK](https://github.com/huntops-blue/huntops-blue.github.io/blob/master/rock-install.md#deploy-rock)

## VirtualBox Installation Instructions
If you're using VMWare Fusion, go to those [instructions](https://github.com/huntops-blue/huntops-blue.github.io/blob/master/rock-install.md#vmware-fusion-installation-instructions)

1. Install VirtualBox
1. Create a New Virtual Machine, Type: "Linux", Version: "Red Hat (64-bit)"
1. Memory size: `12288`
1. Accept the defaults for Hard disk, make the size `50.00` Gb or more
1. Select the new VM, click on "Settings"
1. In Processor, change to `4`
1. In Storage, click on the "CD" icon, then on the "CD" icon next to "Optical Drive", "Choose a disk file..." and select the ROCK ISO you downloaded
1. In Network, click on Adapter 1, click on Port Forwarding
1. Add one for HTTPS, Host IP: `127.0.0.1`, Host Port: `4443`, Guest IP: `10.0.2.15`, Guest Port: `443`
1. Add one for SSH, Host IP: `127.0.0.1`, Host Port: `2222`, Guest IP: `10.0.2.15`, Guest Port: `22`
1. In Network, click on Adapter 2, enable it, and set it to "Internal Network"
1. Move onto [deploying ROCK](https://github.com/huntops-blue/huntops-blue.github.io/blob/master/rock-install.md#deploy-rock)

# Deploy ROCK
Now that we've prepped the hypervisors, let's install ROCK.

1. Start the VM
1. Select "Automated install of ROCK x.x.x-xxxx"
1. Click on "USER CREATION", make sure you check the "Make this user administrator" box
1. Type `c` to continue
1. Log in and type `sudo rock setup` to launch the Text User Interface (TUI)
1. Navigate through the menu items, generally speaking, you can just use the defaults for the Interfaces, setting Management IP, Online or Offline, enable all components
1. Write Config
1. Run Installer - this takes about 10 minutes

# Getting Data Into ROCK
Finally, let's get data into ROCK.

Download some malicious pcap. I like to use [Malware Traffic Analysis](https://www.malware-traffic-analysis.net)
Example:
```
curl -OL [malware file.pcap.zip]
unzip [file.pcap.zip] (password: infected)
sudo tcpreplay -t -i [monitor interface] [file.pcap]
```
*Note: the `-t` flag in `tcpreplay` will fire the traffic all at once and may overrun you network socket buffer and cause you to drop traffic. Remove the `-t` flag if you have this issue, but `tcpreplay` will run for as long as it took the pcap to be captured - so a 2 hour pcap will take 2 hours to replay.*

# Logging into ROCK
In the home directory of the user you created during the installation, there is a file called `KIBANA_CREDENTIALS.txt`. In there you'll find your username and passphrase.

Browse to `https://ROCK_IP_ADDRESS` and use the Kibana credentials to log in.

Pop over to the [blog](https://huntops.blue) for pcap examples in ROCK.

# Troubleshooting
If you run into issues, feel free to check out the [ROCK documentation](https://docs.rocknsm.io), the [ROCK community page](https://community.rocknsm.io), or the [ROCK Github page](https://github.com/rocknsm/rock).
