# UniFi Dream Machine review  
I have recently decided to transform my home network and during the process, I have acquired some new security gadgets. One of them is the UniFi Dream Machine that acts as a home security gateway. I have been extensively using the appliance for some time now and thought I would share some of my findings with this IoT device. Let me know what tips and tricks have you discovered with your UDM.  

## The package  
![01](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/01.png)
![02](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/02.png)
![03](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/03.png)
![04](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/04.png)
![05](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/05.png)
![06](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/06.png)

## Setup and connectivity  

### Unboxing  
* The box comes with cling film wrapping and is fairly light (~2 kg). Inside, we have the white cylinder looking appliance (~1 kg) in a paper holder, an AC power cord and a short quick start guide on how to set up the device.

### Looks  
* The device has a LED halo ring on top of it, which emits either white or blue light depending on the state the appliance is currently in.
* The emitted blue light is a strong one, I do not recommend sleeping next to it or in the same room, as the constant blue light will wake you up.

### LED	Status  
Color | Indication
------------ | -------------
White	| Device is ready to be configured
Flashing White | Device is booting up/initializing/deinitializing
Heartbeat White | Firmware update in process
Blue | Device is configured and ready
Slow Flashing Blue | Client connected to device via Bluetooth (BLE)
Flashing Off/White/Blue | Device is in recovery mode

* There is an option to Locate the device in case someone displaces it inside the house. The appliance will start to flash its LED in blue color.  
![24](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/24.png)

* The device has a built-in speaker, which emits a certain tone when a firmware upgrade is finished or the device rebooted and is ready. This can also be a good indicator when the appliance reboots for some reason.

### Connectivity  
* The appliance has 5 Ethernet Ports (RJ45), 4 LAN ports, an Internet port, a power port and a factory reset button.
* For the evaluation I had connected Port 5 (Internet Port) to my ISP modem.

### Setup  
* The initial setup is done via Mobile Phone App (UniFi Network) and took about 2 minutes to do. The UniFi app uses Bluetooth Low Energy (BLE) for this.  
![07](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/07.png)
![08](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/08.png)
![09](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/09.png)

* Interestingly, during the initial set-up, when asked to create an UI account or log in as already registered, if you took your time at this stage for more than a couple of minutes (~4-5 minutes), the device lost connection and basically forgets all previously configured setting and forces you to do the initial setup from the start. I had found that if you create the account or log in hastily (within ~1-2 minutes), the setup process goes through seamlessly.  
![10](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/10.png)
![11](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/11.png)
![12](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/12.png)

* There is no way to set up the UDM without an active internet connection. If you do not sign up and log in with an UI account, it will refuse to set up the device, also there are zero provisions to set up the UDM offline and then associate an Ubiquiti account later.  
![13](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/13.png)
![14](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/14.png)
![15](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/15.png)
![16](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/16.png)
![17](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/17.png)
![18](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/18.png)

## Firmware  
* During the initial setup, the Mobile App requested an upgrade to be pulled and flashed the device with firmware version v1.5.6, which was released early 2020.
* After this, the device did not offer any further available update. Manually initiated Check new updates from the UI, but this came back as Your device is up-to-date. This mechanism seems to be not working properly, as looking up the support/community forums it was clear that the device can be upgraded to the most recent version v1.8.5, which I did manually through SSH. Link and hash to the v1.8.5 firmware binary: (dcf4d63a8dfe6dc11cef73d53105e6eccc33a258c2a8eb233af426d5d5990004).
  * UDM-Base uses ARM SoC Alpine AL-324 from Annapurna Labs
    * Annapurna Labs Alpine AL-314 @1.7Ghz Quad Core ARM Cortex-A57
    * Alpine is a family of ARM SoCs designed by Annapurna Labs and introduced in 2016 for embedded networking devices. Alpine chips are found in various home gateways, routers, NAS devices, and other network devices.

## Temperature  
* During the first 30 minutes of usage, the appliance was moderately warm.
* After 24 hours of continuous usage, the temperature of the device felt the same.
* The appliance has an active fan inside, which spins up intermittently, usually when the utilization gets higher/more resources are used.
* The sound of the fan can get very high (swooshing), but never spun more than ~30 seconds at that high RPM rate, after which it cools down and stays at a lower RPM, which is inaudible.
* Currently, there aren’t any options to manually set the rate of the RPM.

## Speedtest  
* After the initial setup is done, the device does a speed-test for Downloading, Uploading and measures latency. The test measurements were consistent and gave the right results for my fiber line.
* From the UI, this speedtest looks to be an implementation of WiFiman.com, which has both web and App version.
* The mobile app also asks for the ISP's promised Internet Speed to be set, as these parameters will be used to determine whether there is an issue with your Internet line. I assume if promised line speed drops by ~25%, the UI will raise an alert.  
![21](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/21.png)
![22](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/22.png)
![23](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/23.png)

## First Look (UniFi App)  
* The App asks you to trust the server after the setup. The certificate is a self-signed one.
* Devices menu will show your UDM (Firmware information, connected status and WiFi experience).  
![25](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/25.png)
![26](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/26.png)
![27](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/27.png)

* Opening up the UDM will show UDM name, System Uptime, Utilization, Internet Speeds, currently used network resource, Clients and Most active applications.  
![28](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/28.png)
![29](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/29.png)
![30](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/30.png)

* Drilling down further into the device pane, it will show uptime, WiFi channel utilizations on 2G and 5G, active Ethernet Ports and bunch of information on IP address, MAC address, FW version, Memory usage, Load Average.  
![25](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/31.png)
![26](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/32.png)

## Operating system  
* The UDM-Base runs on a custom Linux OS. You can further add functionalities to your UDM with podman containers. The main unifi system is also a single podman container. You can also install pre-built docker images.

## UI/UX (Mobile app)  
* Connected client information  
![33](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/33.png)
![34](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/34.png)
![35](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/35.png)

* Traffic information/breakdown  
![36](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/36.png)
![37](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/37.png)
![38](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/38.png)
![39](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/39.png)
![40](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/40.png)

* Connected clients (before and after fingerprinting)  
![42](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/42.png)
![43](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/43.png)

## UI/UX (Website)  
* Main dashboard can be edited with several widgets (widgets can’t be created by you however)  
![44](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/44.png)
![45](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/45.png)

* Login panel and basic device information  
![48](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/48.png)

* New login panel in v1.8.5 with 2FA  
![49](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/49.png)

* Map for all devices, you can also upload a custom floor plan and spread the devices out on that  
![50](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/50.png)
![51](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/51.png)

## Security Features  

### Firewall  
* Conventional firewall rules can be implemented on L3/L4 level with Allow or Block action on both In or Out direction.
* Restrict Access to ToR: When enabled will block access to The Onion Router. 
* Restrict Access to Malicious IP Addresses: When enabled will block access to IP addresses or blocks of addresses that have been recognized as passing malicious traffic.  
![52](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/52.png)

### Network Isolation  
![53](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/53.png)
![54](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/54.png)
![55](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/55.png)
![56](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/56.png)

### GeoIP Filtering
* Blocking can be done from the Settings page as well by specifying the country and adding the action to it (Block/Allow) and specify direction (In/Out/Both)
* Maximum number of blocked countries is only 150
* Blocking individual countries can be configured on the Threat Management Dashboard section of the controller. Blocking is as easy as navigating to the map, clicking on a country, and confirming by clicking "Block".  
![57](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/57.png)
![58](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/58.png)
![59](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/59.png)

### DNS Filtering  
* Clients that use VPN, DNS-over-HTTPS, or DNS-over-TLS will have non-standard DNS requests that will not be seen by the device.
* Three filter levels:
  * Security: Blocks access to phishing, spam, malware, and malicious domains. The database of malicious domains is updated hourly. Note that it does not block adult content.
  * Adult: Blocks access to all adult, pornographic and explicit sites. It does not block proxy or VPNs, nor mixed-content sites. Sites like Reddit are allowed. Google and Bing are set to the "Safe Mode". Malicious and Phishing domains are blocked.
  * Family: Blocks access to all adult, pornographic and explicit sites. It also blocks proxy and VPN domains that are used to bypass the filters. Mixed content sites (like Reddit) are also blocked. Google, Bing, and Youtube are set to the Safe Mode. Malicious and Phishing domains are blocked.
* UniFi DNS filter uses a simple host-based filter from cleanbrowsing.org.

### Device Fingerprinting  
* UniFi UDM relies on 3 ways to identify/fingerprint devices on the network:
  * Device OUI
  * Propriety Fingerprint Library
  * User Submission
* Device Fingerprinting Settings  
![60](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/60.png)
![61](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/61.png)
![62](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/62.png)
![63](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/63.png)
![64](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/64.png)
![65](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/65.png)
![66](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/66.png)

* When a device is first connected to the network, it gets assigned a fingerprint based on OUI
* A user can decide to manually assign a Manufacturer to the device in case it has a missing icon, or current one is wrong
* Here the device type was determined via the Fingerprint Library

### Parental Control
* For Parental Control, we have 3 settings
  * All sites are allowed
  * Work profile, explicit, pornographic, and malicious domains are blocked
  * Family profile, VPN, explicit, pornographic and malicious domains are blocked  
![67](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/67.png)

* You can also specify which certain Application or Family of applications should not pass the gateway (Youtube/Office/File sharing services, etc.) and these can be individually selected for block  
![68](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/68.png)

* The UDM also has the option to limit the availability of the WiFi for certain hours, limiting how kids can connect to the WiFi  
![69](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/69.png)

### Adblocking/Privacy  
* No specific Ad-blocking capabilities were observed.

### Anti-DoS  
* Currently no anti-DoS features are present in UDM. Once the IPS module (Suricata) is enabled, you can enable the emergingthreat-dos ruleset, that looks for certain patterns of DoS and can block them, but only on the UDM-Pro appliance, due to memory limitations.

### Safe Browsing features  
* Blocking malicious domains can be achieved via the:
  * Restrict Access to Malicious IP addresses option that use the clearbrowsing.org service
  * Or via Suricata IDS/IPS module  
![70](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/70.png)

### IPS/IDS  
* Enabling the IDS/IPS module (Suricata) will decrease the maximum throughput of the WAN port to 850 Mbps on the UniFi Dream Machine (UDM-Base) throughput: 850 Mbps and to 3.5 Gbps on the UniFi Dream Machine Pro (UDM-Pro). Enabling Device Fingerprinting will also incur some penalty on the throughput.
* The current Suricata version in use by UDM is version 4.1.8 which is End of Life. Representatives of Ubiquiti claim that the development team still heavily focuses on keeping the version 4 branch alive by adding security patches and fixes to it.  
![71](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/71.png)

* Due to the amount of available memory (2 GB) on the UDM-Base only a limited selection of threat categories can be enabled.
* While on the UDM-Pro, the following set of ET rules could be enabled, due to the fact it has 2 GB of internal memory.
* The whitelisting function of the IPS engine allows a UniFi Administrator to create a list of trusted IP's. The traffic, depending on the direction selected, will not get blocked to or from the identified IPs. 
* Suricata Dashboard  
![72](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/72.png)

* Suricata Settings Page (increasing the sensitivity level enables further rule files, and eats more RAM)  
![73](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/73.png)

* ET rule categories  
![74](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/74.png)

### Threat scanner  
* This feature claims to auto-scan endpoints connected to the network to identify vulnerabilities.  
![75](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/75.png)

* It will try and ascertain 3 parameters of a host:
  * IP address
  * Operating system (best effort)
  * Open ports  
![76](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/76.png)

* The endpoint scanner will initiate the port scanning against a host, when the uptime of the newly connected device reaches 2 hours
* Once the scan is done, results will be displays under Threat Management/Endpoint Scanning.
* If no open ports were found, no entry will be in this action, so for a host to show up here, at least one port needs to be in open state.  
![77](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/77.png)

* The endpoint scanner gets invoked with **nmap -sV -O -oG** parameters

### Honeypot
* There is a feature to turn on an internal honeypot to detect malware, worms and other types of malicious traffic attempting to scan your network for vulnerabilities.
* The "internal honeypot" feature is a passive detection system that listens for LAN clients attempting to gain access to unauthorized services or hosts. Clients that are potentially infected with worm or exfiltration type vulnerabilities are known to scan networks, infect other hosts, and potentially snoop for information on easy-to-access servers.
  * First you have to specify an IP address outside of DHCP IP range (for ex. 192.168.2.2)  
![78](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/78.png)

* Scanning from another host, the IP 192.168.2.2 shows plenty of open ports:
* The scanning activity also shows up under the Honeypot pane on the UI, but there is not many action that you can take
  * The only option is to block the IP the client is coming from, so no further scans can be initiated  
![79](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/79.png)

* Manually calling up on port 8080 reveals some fake HTTP 400 page
* You can also connect to open TCP port 23 and gibberish data and a login prompt will come back, but all default password fails

```javascript
neo@amp  ~  nc 192.168.2.2 23
����������!��Debian GNU/Linux 8
login: debian
Password: debian
Login incorrect
```

## Overview of all settings  

### WiFi  
#### Add New WiFi Network  
* Multiple APs, AP groups
* UAPSD Unscheduled Automatic Power Save Delivery
* High Performance Devices, 5Ghz
* Proxy ARP, remaps ARP table for station
* Legacy 11b support
* Mutlicast Enhancement, send multicast at higher datarate
* BSS transition, with WNM
* L2 isolation
* Enable Fast Roaming, .11r compa
* Rate-limiting Bandwith profiles
* PMF, protected mgmt frames
* RADIUS, MAC auth
* MAC address filter
* WiFi scheduler
#### Add New Guest Hotspot  
* Guest Portal
* Auth type:
  * RADIUS
  * We Chat
  * Payment
  * Vouchers
  * Password
  * Facebook
  * External Portal Server
* Portal design
  * Customizable design
  * Custom ToS
* Customizable Landing Page
  * Multiple Language
  * HTTPS redirection

### Networks  
#### Add new network  
  * Internet Access (Coming Soon)
  * Backup WAN Access (Coming Soon
  * Add VPN Type
  * Content Filtering settings (None/Work/Family)
  * Set VLAN
  * Device Isolation
  * IGMP Snooping
  * Auto Scale Network
  * DHCP Server Settings
  * IPv6 sesttings

### Security  
#### Internet Threat Management  
* Intrusion Detection System/Intrusion Prevention System
  * Customize Threat Management
    * Virus & Malware
    * Botcc
    * Mobile Malware
    * Malware
    * WORM
    * P2P
    * Tor
    * Hacking
    * Exploit
    * Shellcode
    * Internet Traffic
    * DNS
    * User-Agents
    * Bad Reputation
    * Dshield
* Threat Scanner
* Internal Honeypot
* Firewall Rules
* Advanced
  * Restrict access to malicious IP addresses
  * Restrict access to Tor
  * Threat Management Allow List
  * Signature Supression
#### Traffic & Device Identification  
* Enable Deep Packet Inspection
* Device Fingerprinting
* Restriction Definitions
* Restriction Assignments

### Internet  
#### WAN  
  * DNS servers
  * Set VLAN ID
  * Enable Smart Queues (Prioritize traffic)
  * IPv4 connection settings
  * IPv6 connection settings

### System Settings  
#### Maintenance  
* Update/Restore
* Statistics Data Retention
* Support Information
#### UniFi AI  
* WiFi AI
  * AP switching channels to the most optimal one, avoiding interference
#### Controller Configuration  
* Remote Logging
* Uplink Connectivity Monitor (Monitor AP uplink connection)
* Network Time Protocol (NTP)
* Device SSH Authentication
* Mail Server

### Advanced Features  
#### Switch Ports  
* Add a Port Profile
  * PoE Mode
  * Advanced Options
    * 802.1X Control
    * Port Isolation
    * Storm Control
    * Spanning Tree Protocol (STP)
    * LLDP-MED
    * Egress Rate Limit
#### Network Isolation  
* VLAN ID
* IGMP Snooping
* DHCP Guarding
#### Bandwidth Profile  
* Limit download/upload limit
#### RADIUS  
* RADIUS settings
  * Enable Wired/Wireless 
  * Enable Accounting
  * Authentication Server
#### Advanced Gateway Settings  
* Port Forwarding
* Static Routes
* Dynamic DNS
* DHCP
  * DHCP Relay
  * DHCP Options
* Multicast DNS
* SIP
  * SIP Endpoint
* UPnP
* SNMP

## 3rd party addons/plugins  

* https://github.com/tusc/ntopng-udm  
* https://github.com/boostchicken/udm-utilities  
* https://github.com/alsmith/multicast-relay  
* https://github.com/shuguet/openconnect-udm  
* https://github.com/kchristensen/udm-le  
* https://github.com/ntkme/unifi-entrypoint  
* https://github.com/mtalexan/udm-instructions  
* https://github.com/cpriest/udm-patches  
* https://github.com/heXeo/ubnt-fan-speed  
* https://github.com/pbrah/eap_proxy-udmpro  
* https://github.com/cdchris12/UDM-DNS-Fix  

## CVE-UBNT  

* https://www.cvedetails.com/vulnerability-list/vendor_id-12765/Ubnt.html  
* https://www.cvedetails.com/vulnerability-list/vendor_id-16054/Ubiquiti-Networks.html  
* https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=ubiquiti  

## Verdict  

* It is a feature-rich IoT security gateway for home power users  
* Some of those features are still in Alpha or Beta stage and need further development to iron out bugs and inconsistencies  
* On UX/UI front, Ubiquiti does more than a great job, visuals are sleek and minimalist  
* While old classic settings page shows all features, new settings pane does not show everything, the new settings page is still under development it seems  
* Some of those security features are implemented in the most basic sense (DNS filtering with a simple blocklist, no DNS-over-HTTP or other advanced features)  
* No Anti-DoS module, but Suricata makes up for that  
* No ad-blocking
* Suricata is still on version 4.1.8, which is End-of-Life, could use an upgrade to v5 or v6  
