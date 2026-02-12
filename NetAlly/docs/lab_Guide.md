
Establish L2VPN Pseudowire with NSO WEBUI 

1. Requirements:

L2VPN - MPLS Pseudowire.

 

2. Lab Objective:

This lab use NSO (Cisco Network Orchestration) software had L2VPN services model, just focus using WEBUI and NSO CLI to establish L2VPN.

 

3. Protocols:

OSPF.

MPLS-LDP.

Xconnect.

Pseudowire class.

 

4.Lab Guide:

This lab has 4 steps to establish L2VPN:

step 1: Make sure connections between NSO with Admin, NSO with routers in topology
step 2: Create device templates and match them with devices in topology
step 3: Establish L2VPN: CE01 - CE04, CE02 - CE03 and check results.
 

5. Lab Topology:


 

6. Lab Setup:

- All routers have startups config to create hostname, domains, username/password/second_password is  nso/123/123, and set IP address on interfaces that link to NSO. Username and password to login NSO: admin / admin.

- Using NSO simulation platform version 5.3 base on Ubuntu-20.04 container of Docker, Chrome platform to use Web GUI of NSO, you need download these devices to use:



7. Guide:

Step 1: 

Need enable SSHv2 key on all Routers by below commands:

crypto key generate rsa
1024
On NSO, login with admin/admin then start NSO software:

root@NSO:/home/admin# source /home/NSO/nso-5.3/ncsrc
root@NSO:/home/admin# cd /home/NSO/ncs-run/
root@NSO:/home/NSO/ncs-run# ncs
and wait until NSO starting successful, in chrome of admin node, you can connect to NSO WEBUI, login NSO with default user/pass admin/admin like this:


or you can connect NSO CLI with this command:

root@NSO:/home/admin# ssh admin@127.0.0.1 -p 2024

 In this mode, NSO suport non-Cisco devices, all devices in this lab are Cisco devices, so you will enable Cisco CLI by this command:

admin@ncs> switch cli
 

Step 2:

Create device templates which NSO match with devices. in CLI mode, start with P01 Router:

admin@ncs# config
admin@ncs(config)# devices authgroups group lab default-map remote-name nso remote-password 123 remote-secondary-password 123
admin@ncs(config-group-lab)# top
admin@ncs(config)# devices device P01
admin@ncs(config-device-P01)# address 10.10.10.1 port 22
admin@ncs(config-device-P01)# device-type cli ned-id cisco-ios-cli-3.8 protocol ssh
admin@ncs(config-device-P01)# state admin-state unlocked
admin@ncs(config-device-P01)# authgroup lab
you can see your configure with XML (CLI or Native) format by this command:

admin@ncs(config-device-P01)# commit dry-run outformat xml 

confirm your configure with this command:

admin@ncs(config-device-P01)# commit

then get key SSH for connection:

admin@ncs(config)# devices fetch-ssh-host-keys 

synchronize this template with devices in topology by this command:

admin@ncs(config)# devices sync-from

in WEBUI:


You can create devices template by WEBUI:


Click "PE02" to setup device:


Set view options like this to hide actions and data:


 


 


 


 


 


 


 


 


Check you input and commit to confirm:


Run "fetch-ssh-host-keys" action to create SSH key: 


like this:


Check templates with devices:


Continue with other Routers.


 

 

Step 3:

Establish L2VPN: CE01 - CE04, CE02 - CE03.

With CE1-CE4, we will establish with NSO CLI:

Picture below that all you need configure if you configure by routers CLI.



admin@ncs(config)# services L2VPN CE1-CE4 pseudowire 14 device-name1 PE02 interface-num1 0/1 remoteIP-1 3.3.3.3 device-name2 PE03 interface-num2 0/1 remoteIP-2 2.2.2.2
admin@ncs(config-L2VPN-CE1-CE4)# commit

on WEBUI:


Check connections:


 

With CE2-CE3, we can create L2VPN by WEBUI:


 


 


 


 


 


"COMMIT", redeploy and check connections.

 