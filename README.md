# ebpf-for-gfw
Countering GFW Active Probing with an ebpf based Whitelist Firewall

This is an ebpf xdp based solution to use whitelist to block active probing from GFW.

The ebpf program will check every TCP SYN packet to the VPN port (443) and server prefix (10.0.x.x).
Will pass if it match the whitelist (the whitelist is /24 based not /32). Will drop if not.

The ebpf program will check every UDP packet to the port range (1000-2000) and server prefix (10.0.x.x).
Will add the source ip /24 prefix into whitelist if it match the signature set from the .ps1 script.

ps1 script is a windows powershell script that will try to whitelist the client's source ip every 30 seconds, this need to be running on the client side.

This solution is not perfect, but should be good enough. If GFW use replay attack on the UDP whitelist port, it technically might bypass the whitelist. But since GFW's active probe will not replay packet this small, even if they replay packet this small, it will unlikely to send a follow up shadowsock probe packet using the same source IP and right VPN port (very unlikely).

To make this solution better, the XDP should send a challenge back to the ps1 script and ps1 script need to sign it and send it to the XDP again. XDP validate the sign and add to whitelist only if sign is correct.
