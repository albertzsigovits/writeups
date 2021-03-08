# Corelight NSM@Home program review  

Recently Corelight came out with a Software Sensor package for home users. This NSM@Home package is a trimmed down version of the original Software Sensor they offer for their customers. I have installed their sensor on a Raspberry Pi 4 B developer board and tested it for a few days. Here are some findings:  

* The software sensor can be installed on any Linux plaforms or containers  
* Under the hood, Corelight Sensor consists of Zeek, a network traffic analyzer and parser  
* Another engine is Suricata, a network intrusion detection system  
* Zeek can analyze and log traffic for 35+ different network protocols (TCP, HTTP, SSL, SMB, DNS, SNMP, SMTP, RDP, DHCP, etc..)  
* Suricata comes with Emerging Threats PRO signatures  
* Can collect encrypted traffic, breakdown of certificate information  
* It can extract files from the network stream through different parsers  
* Plugins and scripts can be created, even for specific vulnerabilities (many CVE specific script)  
* The binary of the software sensor is about ~60 MB  
* Flexbile deployment, capacity-based licensing model  
* Zeek can export logs to Kafka, Redis, Logstash  
* Support for Elastic Connector, Splunk App, Humio Cloud  
* REST API  

## NSM@Home  

* NSM@Home software sensor package is a trimmed down version of the original software sensor
* Size of the binary is around ~30 MB (ARMv7)

## Setup  

* Apply for the NSM@Project through Corelight’s website
* Get your credentials in e-mail
* Download the license file from the Adaptive site
* Get a RPi4B model with 8GB RAM and a relatively big mSD card
* Image the Raspberry Pi OS
* Install the corelight package
* Set up a TAP port to mirror traffic to a switch port
* Link the RPi4 to that port
* Send network logs to a Humio, Splunk or to a ELK instance

## Quick Menu  

## Quick Config  

## Health Check  

* Interface statistics
* Disk space
* The Raspbian OS x86 and the Corelight package together takes up ~7 GB of disk space
* Connectivity checks
* CPU and GPU temperature
* Pretty much fixed around ~60' C

### Used resources  

* The corelight software package (home version) eats up around ~900 MB of RAM constantly.
* Around ~400 MB from that is just used for the suricata module.
* The corelight-softsensor (zeek package) uses ~500 MB of RAM.

## Splunk integration  

* Set values in HEC exporter section of /etc/corelight-softsensor.conf  
* Set up HTTP Event Collector/HEC in Splunk Data sources section
* https://docs.splunk.com/Documentation/Splunk/8.1.2/Data/UsetheHTTPEventCollector?ref=hk

## Humio integration  
* By default logs are sent to Humio cloud. In Humio you can use all sorts of queries or dashboards to look at the data the softsensor collected.

## Installed files  
When the corelight softsensor is deployed, the following files are placed on to the system:
```
/etc/corelight-license.txt
/etc/corelight
/etc/apt/sources.list.d/corelight-softsensor.list
/etc/apt/auth.conf.d/corelight-softsensor.conf
/etc/systemd/system/corelight
/etc/systemd/system/multi-user.target.wants/corelight-softsensor.service
/etc/corelight-softsensor.conf.example
/etc/corelight-softsensor.conf
/usr/share/doc/corelight-softsensor
/usr/bin/corelight-softsensor
/usr/bin/raspi-corelight
/usr/bin/corelight-suricata
/usr/lib/systemd/system/corelight-softsensor.service
/var/corelight
/var/corelight/logs/
/var/corelight/spool/supervisor/corelight_supervisor_status.log
/var/lib/dpkg/info/corelight-softsensor.list
/var/lib/dpkg/info/corelight-softsensor.conffiles
/var/lib/dpkg/info/corelight-softsensor.prerm
/var/lib/dpkg/info/corelight-softsensor.md5sums
/var/lib/dpkg/info/corelight-softsensor.postinst
/var/lib/apt/lists/pkgs.corelight.com_deb_stable_dists_buster_main_binary-arm64_Packages
/var/lib/apt/lists/pkgs.corelight.com_deb_stable_dists_buster_InRelease
/var/cache/apt/archives/corelight-softsensor_1.3.3_arm64.deb
```

### /etc/apt/sources.list.d/corelight-softsensor.list  
```
deb [arch=arm64] https://pkgs.corelight.com/deb/stable buster main
```

### /etc/apt/auth.conf.d/corelight-softsensor.conf  
```
machine pkgs.corelight.com/deb/stable
 login albert.zsigovits@corelight-ext
 password -
```

### /etc/systemd/system/corelight  
```
[Unit]
Description=Corelight Software Sensor
After=network.target

[Service]
ExecStart=/usr/bin/corelight-softsensor start
KillMode=mixed
TimeoutStopSec=10s
LimitNOFILE=infinity
LimitNPROC=infinity
TasksMax=infinity

[Install]
WantedBy=multi-user.target
Alias=corelight
```

### /var/lib/dpkg/info/corelight-softsensor.conffiles  
```
/etc/corelight-softsensor.conf.example
/etc/corelight/EULA
/etc/corelight/input_files/.keep
/etc/corelight/local.zeek
/etc/corelight/rules/.keep
```

### /var/lib/dpkg/info/corelight-softsensor.list  
```
/.
/etc
/etc/corelight
/etc/corelight/local.zeek
/etc/corelight/rules
/etc/corelight/rules/.keep
/etc/corelight/input_files
/etc/corelight/input_files/.keep
/etc/corelight/EULA
/etc/corelight-softsensor.conf.example
/lib
/lib/systemd
/lib/systemd/system
/lib/systemd/system/corelight-softsensor.service
/usr
/usr/share
/usr/share/doc
/usr/share/doc/corelight-softsensor
/usr/share/doc/corelight-softsensor/changelog.gz
/usr/bin
/usr/bin/corelight-softsensor
/usr/bin/corelight-suricata
```

### /var/lib/dpkg/info/corelight-softsensor.md5sums  
```
7df80cd1f84b4db2da1ed7fb3e358198  etc/corelight/EULA
d41d8cd98f00b204e9800998ecf8427e  etc/corelight/input_files/.keep
37657d999cee5606c54deea27020932c  etc/corelight/local.zeek
d41d8cd98f00b204e9800998ecf8427e  etc/corelight/rules/.keep
c37c848c41ea37bef6934508a37f8d2d  etc/corelight-softsensor.conf.example
4fedd5cf3b1aea0c8a1d6155058ec54a  lib/systemd/system/corelight-softsensor.service
64539f0f4296985c6bcb4a161ea22221  usr/bin/corelight-softsensor
f59ff0ed47a376cb36c701314910ea32  usr/bin/corelight-suricata
4b2c2c3332bb8fd7b295307a2eb7dc16  usr/share/doc/corelight-softsensor/changelog.gz
```

### /var/lib/dpkg/info/corelight-softsensor.prerm  
```
#!/bin/sh
before_remove() {
    :

systemctl stop corelight-softsensor >/dev/null || true
systemctl disable corelight-softsensor >/dev/null || true
systemctl --system daemon-reload >/dev/null || true
}

dummy() {
    :
}

if [ "${1}" = "remove" -a -z "${2}" ]
then
    # "before remove" goes here
    before_remove
elif [ "${1}" = "upgrade" ]
then
    # Executed before the old version is removed
    # upon upgrade.
    # We should generally not do anything here. The newly installed package
    # should do the upgrade, not the uninstalled one, since it can't anticipate
    # what new things it will have to do to upgrade for the new version.
    dummy
elif echo "${1}" | grep -E -q "(fail|abort)"
then
    echo "Failed to install before the pre-removal script was run." >&2
    exit 1
fi
```

### /var/lib/dpkg/info/corelight-softsensor.postinst  
```
#!/bin/sh
after_upgrade() {
    :

systemctl --system daemon-reload >/dev/null || true
if ! systemctl is-enabled corelight-softsensor >/dev/null 
then
    systemctl enable corelight-softsensor >/dev/null || true
    systemctl start corelight-softsensor >/dev/null || true
else
    systemctl restart corelight-softsensor >/dev/null || true
fi
}

after_install() {
    :

systemctl --system daemon-reload >/dev/null || true
systemctl enable corelight-softsensor >/dev/null || true
systemctl start corelight-softsensor >/dev/null || true
}

if [ "${1}" = "configure" -a -z "${2}" ] || \
   [ "${1}" = "abort-remove" ]
then
    # "after install" here
    # "abort-remove" happens when the pre-removal script failed.
    #   In that case, this script, which should be idemptoent, is run
    #   to ensure a clean roll-back of the removal.
    after_install
elif [ "${1}" = "configure" -a -n "${2}" ]
then
    upgradeFromVersion="${2}"
    # "after upgrade" here
    # NOTE: This slot is also used when deb packages are removed,
    # but their config files aren't, but a newer version of the
    # package is installed later, called "Config-Files" state.
    # basically, that still looks a _lot_ like an upgrade to me.
    after_upgrade "${2}"
elif echo "${1}" | grep -E -q "(abort|fail)"
then
    echo "Failed to install before the post-installation script was run." >&2
    exit 1
fi
```

### tree /etc/corelight/  
```
/etc/corelight/
├── EULA
├── input_files
├── local.zeek
├── rules
│   └── suricata.rules
└── suricata-update
    ├── custom_rules
    ├── disable.conf
    ├── enable.conf
    ├── modify.conf
    └── update
        └── cache
            ├── 70d9eddbf429eafe2b741e615a00a74a-emerging.rules.tar.gz
            └── index.yaml
```

### /etc/corelight-softsensor.conf  
```
# You only need to set the following value if the hostname the system has already is
# not an acceptable name to use in the logs and other export locations.
#Corelight::system_name       corelight-sniff01

# Below is an example "sniff" option.  Interfaces are separated with commas and the number 
# of workers is optionally specified after the interface with a tilde (~).
# If the "corelight" process is already started, once this option is configured, the cluster
# will automatically start up. You don't need to take any additional action.
#Corelight::sniff             eth0~4,eth1~2
Corelight::sniff                eth0

# Corelight::disk_space is the base directory or directory root for the Software Sensor.  All relative
# paths configured below will be based on this directory.
# You likely don't want to change this. By default, the packaged (RPM/DEB) versions of
# the Corelight Software Sensor create this location.
#Corelight::disk_space        /var/corelight

# If you would like to avoid sharing stats with Corelight for debugging and health
# monitoring purposes, change this value to "F".
Corelight_Cloud::share_stats T

# Local networks
Site::local_nets             10.0.0.0/8,192.168.0.0/16,172.16.0.0/12,100.64.0.0/10,127.0.0.0/8,fe80::/10,::1/128

# Zeek script(s) to load. This can normally be left alone and you can edit the local.zeek
# script to load additional scripts.
Corelight::load_scripts      /etc/corelight/local.zeek

# A BPF filter of traffic that you would like to ignore.
Corelight::ignore_bpf        

# The amount of memory in Megabytes that you'd like to set as a maximum allowed per process.
# This can prevent accidental script mistakes or unexpected side effects from completely taking
# over all memory on your system.
Corelight::memory_limit_mb   6500

#####################
# Suricata Settings #
#####################

# Enable or disable Suricata
Suricata::enable       T

# The absolute path to the directory where your rule files are stored.
Suricata::rule_path    /etc/corelight/rules/

# A list of rules to load from the Suricata::rule_path directory.
Suricata::rule_files   *.rules

############################################# 
# Analyzer Specific Settings                #
############################################# 

### WARNING!  This is a beta feature! ###
# Enable the beta archive expansion plugin.  
# This will cause the Software Sensor to dig further into archive files like Zips and tar.gz.
Corelight::archive_expand_enable   F

############################################# 
# Streaming Exporter configs are below here #
#############################################

# JSON into Splunk's HEC (HTTP Event Collector) API
#Corelight::hec_enable          T
#Corelight::hec_url             https://cloud.humio.com/services/collector
#Corelight::hec_token           119e-(secret)-9444
Corelight::hec_enable           T
Corelight::hec_url              http://192.168.80.14:8088/services/collector/event
Corelight::hec_token            7a-(superdoubletopsecret)-6d5e63a
Corelight::hec_sourcetype_prefix  corelight_
Corelight::hec_verify_cert      F

# JSON to a Kafka server
Corelight::kafka_enable          F
Corelight::kafka_servers         1.2.3.4:9092
Corelight::kafka_topic_prefix     
Corelight::kafka_enable_ssl      T
Corelight::kafka_sasl_username    
Corelight::kafka_sasl_password    
Corelight::kafka_ssl_ca_location  

# JSON over TCP export
Corelight::json_enable       F
Corelight::json_server       1.2.3.4:12345

# JSON over TCP syslog export
Corelight::syslog_enable     F
Corelight::syslog_server     1.2.3.4:514
# This is a lower case syslog priority
Corelight::syslog_facility   local0
# This is a lower case syslog severity
Corelight::syslog_severity   info
# Valid optons are rfc5424_octet_framing, rfc5424_non_transparent, or rfc3164
Corelight::syslog_format     rfc5424_octet_framing

# JSON to a redis server.  This can only use the RPUSH command right now.
Corelight::redis_enable      F
Corelight::redis_host        127.0.0.1
Corelight::redis_port        6379
Corelight::redis_password    
# A string that will be prepended to the path name.  If you don't want it, you can leave this field blank.
Corelight::redis_key_prefix  corelight-

####################################
# Batch Log configs are below here #
####################################

# Global settings for batch logs
# This group of settings is not dynamic at the moment and the software sensor must
# be restarted in order to apply them.
Corelight::batch_log_format            json
Corelight::batch_log_rotation_interval 3600
Corelight::batch_log_gzip              F

# Enable/disable writing logs to the disk file system
#  T: Write batch logs to the disk file system, with rotation
#  F: Don't write any logs to the disk file system at all
Corelight::batch_log_disk_enable           T
# If this is a absolute path it will extract there, if relative, it is relative to the base directory
# defined above with (Corelight::disk_space).
Corelight::batch_log_disk_path             ./logs
# Enable this to make the software sensor automatically maintain disk utilization (only if batch_log_disk_enable is T)
Corelight::batch_log_disk_cleanup_enable   F
# Keep disk usage at the specified log storage location under a specified percentage.
Corelight::batch_log_disk_cleanup_pct_max  80

# Batch log export over SFTP
Corelight::batch_log_ssh_enable    F
# Following option are for "sftp"
Corelight::batch_log_ssh_mode      sftp
Corelight::batch_log_ssh_server    1.2.3.4
Corelight::batch_log_ssh_port      22
Corelight::batch_log_ssh_user      username
# Leave this empty is doing key based authentication
Corelight::batch_log_ssh_password  
# Point to a privkey file on disk or encode the privkey directy in this variable hex escaped. (i.e. \xFF)
Corelight::batch_log_ssh_privkey   
# Leave this empty if the key has no passphrase
Corelight::batch_log_ssh_privkey_passphrase  
# Path on the remote file system to write logs.  If relative path given, it will be relative to remote users home dir.
Corelight::batch_log_ssh_path      ./corelight-logs

#########################################
# Extracted File configs are below here #
#########################################

# Global settings for extracted files
Corelight::extracted_files_max_bytes               5242880
# This is an additional way to provide a way to limit files that get extracted based on the "Corelight Filter Language"
#   Documentation for this variable and the language is forthcoming.
Corelight::extracted_files_filter                  

# Global settings to define the types of files to extract.
# Supported MIME types can be seen here: https://github.com/zeek/zeek/tree/master/scripts/base/frameworks/files/magic
# Specify desired mimetypes as a comma separated list and here is an example below:
#Corelight::extracted_files_mime_types             image/jpeg,text/html
Corelight::extracted_files_mime_types              
# These are groups of mimetypes and are added to any mime types above.
Corelight::extracted_files_group_archives          T
Corelight::extracted_files_group_executables       T
Corelight::extracted_files_group_flash             T
Corelight::extracted_files_group_java              T
Corelight::extracted_files_group_office_documents  T
Corelight::extracted_files_group_pdfs              T

# Extracted file export to local file system
Corelight::extracted_files_disk_enable          F
# If this is a absolute path it will extract there, if relative, it is relative to the base directory
# defined above with (Corelight::disk_space).
Corelight::extracted_files_disk_directory    ./extracted_files
# Enable this to make the software sensor automatically maintain disk utilization. (only if extracted_files_disk_enable is T)
Corelight::extracted_files_disk_cleanup_enable     F
# Keep disk usage at the specified file extraction location under a specified percentage.
Corelight::extracted_files_disk_cleanup_pct_max    80  

# Extracted file export over SFTP
Corelight::extracted_files_ssh_enable    F
# Following options are for "sftp"
Corelight::extracted_files_ssh_mode      sftp
Corelight::extracted_files_ssh_server    1.2.3.4
Corelight::extracted_files_ssh_port      22
Corelight::extracted_files_ssh_user      username
# Leave this empty is doing key based authentication
Corelight::extracted_files_ssh_password   
# Point to a privkey file on disk or encode the privkey directy in this variable hex escaped. (i.e. \xFF)
Corelight::extracted_files_ssh_privkey    
# Leave this empty if the key has no passphrase
Corelight::extracted_files_ssh_privkey_passphrase
# Path on the remote file system to write files.  If relative path given, it will be relative to remote users home dir.
Corelight::extracted_files_ssh_path      ./corelight-extracted-files

###############################
# Metrics Data Export config  #
###############################

# Prometheus metrics export
CorelightMetrics::prometheus_enable               T
# Set to T in order to produce metrics per process instead of overall totals.
CorelightMetrics::prometheus_metrics_per_process  F
CorelightMetrics::prometheus_listen               192.168.1.5:8989
```

### sudo service corelight-softsensor status  
```
● corelight-softsensor.service - Corelight Software Sensor
   Loaded: loaded (/lib/systemd/system/corelight-softsensor.service; enabled; vendor preset: enabled)
   Active: active (running) since Thu 2021-02-25 19:17:07 CET; 2s ago
 Main PID: 13525 (corelight-softs)
    Tasks: 35
   CGroup: /system.slice/corelight-softsensor.service
           ├─13525 /usr/bin/corelight-softsensor start
           ├─13540 sh -c /usr/bin//corelight-suricata -c /var/corelight/suricata/.suricata.yaml --af-packet #runit#suricata#
           ├─13541 /usr/bin//corelight-suricata -c /var/corelight/suricata/.suricata.yaml --af-packet
           ├─13550 sh -c /usr/bin/corelight-softsensor -- Cluster::node=logger corelight/ /etc/corelight/local.zeek  Corelight::disk_space="/var/corelight" Corelight::system_name="arpi4b" #runit#logger#
           ├─13551 /usr/bin/corelight-softsensor -- Cluster::node=logger corelight/ /etc/corelight/local.zeek Corelight::disk_space=/var/corelight Corelight::system_name=arpi4b
           ├─13555 sh -c /usr/bin/corelight-softsensor -- Cluster::node=manager corelight/ /etc/corelight/local.zeek  Corelight::disk_space="/var/corelight" Corelight::system_name="arpi4b" #runit#manager#
           ├─13556 /usr/bin/corelight-softsensor -- Cluster::node=manager corelight/ /etc/corelight/local.zeek Corelight::disk_space=/var/corelight Corelight::system_name=arpi4b
           └─13565 [zk./usr/bin/cor]

Feb 25 19:17:07 arpi4b systemd[1]: Started Corelight Software Sensor.
Feb 25 19:17:07 arpi4b corelight-softsensor[13525]: Licensed to corelighthome until 2022-02-02 01:00:00 UTC
Feb 25 19:17:07 arpi4b corelight-softsensor[13525]: Info: Read configuration from /etc/corelight-softsensor.conf
Feb 25 19:17:07 arpi4b corelight-softsensor[13525]: Starting Corelight Software Sensor...
Feb 25 19:17:07 arpi4b corelight-softsensor[13525]: Disabling hardware features on eth0 and bringing up the interface...done
```

### Community Zeek packages  
•	https://zeek.org/packages/  
•	https://corelight.com/about-zeek/scripts-and-resources/  
•	https://github.com/corelight/detect-ransomware-filenames   
•	https://github.com/corelight/zeek-elf  
•	https://github.com/corelight/json-streaming-logs  
•	https://github.com/corelight/zeek-community-id  
•	https://github.com/fatemabw/bro-inventory-scripts  
•	https://github.com/hosom/file-extraction  
•	https://github.com/jbaggs/anomalous-dns  
•	https://github.com/vitalyrepin/uap-bro  

### Additional resources  
•	http://www3.corelight.com/nsm@home  
•	https://corelight.blog/2020/11/19/corelight-at-home/  
•	https://www.youtube.com/watch?v=5gL7Ug9H2RE  

![01](https://github.com/albertzsigovits/writeups/blob/main/unifi-udm/images/.png)
