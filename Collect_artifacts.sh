#!/bin/bash
# File: Collect_artifacts.sh
# Author: Christian Rispoli
# CSEC 464

# Add Target Hosts Here
target_hosts=()

# Run on remote hosts; Will timeout after 3 Seconds
read -t 3 -r -p "Do you want to run on target Hosts?" answer

case "$answer" in
	y|Y ) 
		echo "Executing on Hosts"
		# Run on Target Hosts
		for i in "${target_hosts[@]}"; do
			ssh root@$i 'bash -s' < Collect_artifacts.sh
		done;;
	n|N ) echo "Continuing";;
	* ) echo "Invalid";;
esac

if [ $(test -f /tmp/art.config)]; then
	read -n1 -r -p "Please Enter SSH Key Directory" path
	echo $path > /tmp/art.config
else
	path=$(cat /tmp/art.config)
	printf "Using SSH key Directory Path: %s" "$path"
fi

#### Collect time ####
printf "#### Collect time ####\n"
curr_time=$(date)
printf "Current Date\n--------\n%s Mins\n\n" "$curr_time"
uptime=$(uptime | awk -F ' ' '{print $3}')
printf "Current Uptime\n--------\n%s Mins\n\n" "$uptime"

#### Collect OS and Distro Version ####
printf "#### Collect OS and Distro Version ####\n"
osv=$(uname -a)
printf "OS/Distro\n--------\n%s\n\n" "$osv"

#### Collect Host Info ####
printf "#### Host Info ####\n"
host=$(hostname)
domain=$(domainname)
printf "Host Name\n--------\n%s\n\n" "$host"
printf "Domain Name\n--------\n%s\n\n" "$domain"

#### Collect CPU Info ####
cpuinfo=$(cat /proc/cpuinfo)
printf "#### Collect CPU Info ####\n--------\n%s\n\n" "$cpuinfo"

#### Collect memory info ####
meminfo=$(cat /proc/meminfo | grep "MemTotal:")
printf "#### Collect memory info ####\n--------\n%s\n\n" "$meminfo"

#### Collect Storage Info ####
diskinfo=$(fdisk -l)
mounted=$(mounted)
printf "#### Collect Storage Info ####\n--------\n%s\n\n" "$diskinfo"

#### Get User info From /etc/passwd ####
printf "User Information\n--------\n"
for i in $( awk -F ':' '{print $1}' /etc/passwd ); do
	id $i
done
#### Gets the domain information on linux systems ####
domain=$(echo `uname -n`.`awk '/^domain/ {print $2}' /etc/resolv.conf`)
printf "Domain Information\n--------\n%s\n\n" "$domain"

#### Get Scheduled Tasks ####
cjs=$(crontab -l)
printf "CronJobs\n--------\n%s\n\n" "$cjs"

#### Gets logins the are seen by PAM ####
auth=$(cat /var/log/auth.log | grep pam_unix)
printf "Login Info\n--------\n%s\n\n" "$auth"

#### Installed software on the system ####
bin=$(ls -l /bin | awk '{print $9}')
usrbin=$(ls -l /usr/bin | awk '{print $9}')
aptlist=$(apt list --installed)
yumlist=$(yum list installed)
printf "Insatlled Programs\n--------\n%s\n\n" "$usrbin" "$bin" "$aptlist" "$yumlist"

#### Gets all services on the system ####
services=$(service --status-all)
printf "Service Information\n--------\n%s\n\n" "$services"

#### Get Driver/Kern Mod Info ####
kmodules=$(find /lib/modules/$(uname -r) -type f -name '*.ko' | awk '{print $1}')
printf "Kernel Modules\n--------\n%s\n\n" "$kmodules"

#### Gets networking information ####
arpt=$(arp -a)
netconifg=$(ifconfig -a)
dhcpserver=$(cat /var/lib/dhcp/dhclient.eth0.leases | grep "fixed-address" | awk '{print $2}')
dnsserver=$(cat /etc/resolv.conf | grep "nameserver" | awk '{print $2}')
conns=$(netstat -tulpan)

printf "#### TCP/UDP Connections ####\n--------\n%s\n\n" "$conns"
printf "#### Arp Table ####\n--------\n%s\n\n" "$arpt"
printf "#### Network Configuration ####\n--------\n%s\n\n" "$netconfig"
printf "#### DHCP Server Info ####\n--------\n%s\n\n" "$dhcpserver"
printf "#### DNS Server Info  ####\n--------\n%s\n\n" "$dnsserver"

#### List Processes ####
processes=$(ps -aux)
printf "Processes\n--------\n%s\n\n" "$processes"

#### Loop Documents and Directories ####
for D in /home; do
	if [ -d "$D" ];
	then
		for i in /home/$D
		do
			if [ $i == 'Documents' ]; 
			then
				ls /home/$D/$i
			fi
			if [ $i == 'Downloads' ]; 
			then
				ls /home/$D/$i
			fi
		done
	fi
done
