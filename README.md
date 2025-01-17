# ebpf-for-gfw
Countering GFW Active Probing with an ebpf based Whitelist Firewall
This is an ebpf xdp based solution to use whitelist to block active probing from GFW.
The ebpf program will check every TCP SYN packet to the VPN port (443) and server prefix (10.0.x.x).
Will pass if it match the whitelist (the whitelist is /24 based not /32). Will drop if not.

The ebpf program will check every UDP packet to the port range (1000-2000) and server prefix (10.0.x.x).
Will add the source ip /24 prefix into whitelist if it match the signiture set from the .ps1 script.

ps1 script is a windows powershell script that will try to whitelist the client's source ip every 30 seconds, this need to be running on the client side.
