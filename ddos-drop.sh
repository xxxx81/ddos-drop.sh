#!/bin/sh

#config Section
wan_device="" #setting a device between the quotation marks disable auto detection, "" autotection
	          #you can set more then one Wan interface with a comma between the device names for example "eth0,eth1"

bogon="0" #enable Bogon filter "1" enable "0" disable

forward_router="0.0.0.0" #Enter here the Ip address/network of the upstream router if you use the Bogon filter and have a forward router.
			                 #You can add multiple ip addresses or networks with a comma betwen the addresses, network format at example 192.168.0.0/24
syn_flood="0"  #enable syn flood protection

icmp_flood="0" #enable icmp flood protection

udp_flood="0"  #enable udp flood protection

port_scan_detection="0" #enable Portscan detection

arp_limit_enable="0" #enable ARP limit "1" enable "0" disable

wan_input_drop_enable="0"       #Drops inet input to wan interface

wireguard_input_drop_enable="0" #Drops inet input to wireguard interface

reject_with_icmp="0"		#Reject Wan/Wireguard input with Icmp unreachable 

#Parameters

arp_limit="1"	#accepted ARP request per second and on-the-fly per MAC address

syn_flood_limit="25" 	   #syn flood limit

syn_flood_burst_limit="50" #indicates the number of packets that can exceed the rate limit, must be greater than or equal to 1

icmp_flood_limit="15"      #icmp flood limit

icmp_flood_burst_limit="1" #indicates the number of packets that can exceed the rate limit, must be greater than or equal to 1

udp_flood_limit="100"       #udp flood limit

udp_flood_burst_limit="50" #indicates the number of packets that can exceed the rate limit, must be greater than or equal to 1

portscan_limit="50"         #sets the packet limit before the address is blocked

portscan_drop_time="1h"   #Sets the time limit in which the source of the port scan is blocked s=seconds m=minutes h=hours

portscan_src_ports="22" #remote ports for which portscan does not respond  

portscan_dst_ports="22" #target ports for which portscan does not respond

bogon_adresses="0.0.0.0/8, \
		10.0.0.0/8, \
		100.64.0.0/10, \
		127.0.0.0/8, \
		169.254.0.0/16, \
		172.16.0.0/12, \
		192.0.0.0/24, \
		192.0.2.0/24, \
		192.168.0.0/16, \
		198.18.0.0/15, \
		198.51.100.0/24, \
		203.0.113.0/24, \
		224.0.0.0/4, \
		240.0.0.0/4, \
		255.255.255.255/32"

bogon_ipv6_adresses="::/128, \
		     ::1/128, \
		     ::ffff:0:0/96, \
		     ::/96, \
		     100::/64, \
		     2001:10::/28, \
		     2001:db8::/32, \
		     fc00::/7, \
		     fe80::/10, \
		     fec0::/10, \
		     ff00::/8"

#config Section

verbose=false

if [ -z "$wan_device" ]; then

wan_device=$(uci get network.wan.device)

fi

nft list ruleset | grep -q 'DDOS' && nft delete table inet DDOS
nft list ruleset | grep -q 'tcp_portscan' && nft delete table inet tcp_portscan
nft list ruleset | grep -q 'ARP' && nft delete table arp ARP

if [ $arp_limit_enable -ge 1 ]; then

nft -f - <<TABLE
table arp ARP {
	chain Arp_limit { type filter hook input priority 0; policy accept;
	arp operation 1 meter per-mac { ether saddr limit rate $arp_limit/second burst 2 packets } counter accept
	arp operation 1 counter drop
	}
}
TABLE
fi


if [ $port_scan_detection -ge 1 ]; then
nft -f - <<TABLE

table inet tcp_portscan {
          set enemies4 {
                  type ipv4_addr
                  flags dynamic,timeout
                 timeout $portscan_drop_time
         }

         set enemies6 {
                 type ipv6_addr
                 flags dynamic,timeout
                 timeout $portscan_drop_time

	}

    chain portscan_drop { type filter hook prerouting priority -500;
    ip  saddr @enemies4  update @enemies4 { ip  saddr }  counter  drop
    ip6 saddr @enemies6  update @enemies6 { ip6 saddr }  counter  drop
    iifname { $wan_device } tcp flags fin,psh,urg / fin,psh,urg jump input_limit
    iifname { $wan_device } tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 jump input_limit

	}

    chain portscan_detection { type filter hook prerouting priority -160;
    iifname { $wan_device } ct state established,related counter accept
    iifname { $wan_device } tcp sport != { $portscan_src_ports } tcp flags syn,fin,ack,rst th dport != { $portscan_dst_ports } jump input_limit
    iifname { $wan_device } udp dport 1-65535 ct state new jump input_limit

     }

    chain input_limit {
                 limit rate $portscan_limit/second  counter  return
               log prefix "Portscan (drop $portscan_drop_time): " update @enemies4 { ip  saddr } counter drop
               log prefix "Portscan (drop $portscan_drop_time): " update @enemies6 { ip6 saddr } counter drop

	}
}
TABLE
fi

if [[ $reject_with_icmp -ge 1 ]]; then
nft -f - <<TABLE
table inet DDOS {
	chain reject_drop {
	counter reject with icmp type port-unreachable
	counter reject with icmpv6 type port-unreachable
	counter drop
        }
    }
TABLE
else
nft -f - <<TABLE
table inet DDOS {
         chain reject_drop {
	 counter drop
         }
     }
TABLE
fi;

if [[ $syn_flood -ge 1 ]]; then
nft -f - <<TABLE
                 table inet DDOS {
		chain syn_flood {
		limit rate $syn_flood_limit/second burst $syn_flood_burst_limit packets return comment "Accept SYN packets below rate-limit"
		counter drop comment "Drop excess packets"
		}
}
TABLE
else
nft -f - <<TABLE
                  table inet DDOS {
                 chain syn_flood {
		return
		}
}
TABLE
fi;

if [[ $icmp_flood -ge 1 ]]; then
nft -f - <<TABLE
                 table inet DDOS {
		chain icmp_flood {
		limit rate $icmp_flood_limit/second burst $icmp_flood_burst_limit packets return
		counter drop comment "Drop excess packets"
	}
}
TABLE
else
nft -f - <<TABLE
                  table inet DDOS {
                 chain icmp_flood {
		 return
	}
}
TABLE
fi;

if [[ $udp_flood -ge 1 ]]; then
nft -f - <<TABLE
                 table inet DDOS {
		chain udp_flood {
		limit rate $udp_flood_limit/second burst $udp_flood_burst_limit packets return
		counter drop comment "Drop excess packets"
		}
}
TABLE
else
nft -f - <<TABLE
                  table inet DDOS {
                 chain udp_flood {
		return
		}
}
TABLE
fi;


nft -f - <<TABLE

		table inet DDOS {

  	  chain filter_ddos {
        	type filter hook prerouting priority -495;

        iifname { $wan_device } jump flags_input
        
        }

        chain flags_input {
       
		tcp flags syn / fin,syn,rst,ack jump syn_flood comment "!fw4: Rate limit TCP syn packets"

		ip protocol icmp icmp type {echo-reply, destination-unreachable, source-quench, redirect, echo-request, time-exceeded, parameter-problem, timestamp-request, timestamp-reply, info-request, info-reply, \
		 address-mask-request, address-mask-reply, router-advertisement, router-solicitation} jump icmp_flood

		ip protocol icmpv6 icmpv6 type {destination-unreachable, packet-too-big, time-exceeded, echo-request, echo-reply, mld-listener-query, mld-listener-report, mld-listener-reduction, nd-router-solicit, \
		 nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect, parameter-problem, router-renumbering} jump icmp_flood

	ip frag-off & 0x1fff != 0 counter drop
	tcp flags syn \
			tcp option maxseg size 1-535 \
			counter drop
    	meta l4proto tcp tcp flags syn / fin,syn,rst,urg,ack,psh accept
	meta l4proto tcp tcp flags fin / fin,syn,rst,urg,ack,psh accept
	meta l4proto tcp tcp flags rst / fin,syn,rst,urg,ack,psh accept
	meta l4proto tcp tcp flags ack / fin,syn,rst,urg,ack,psh accept
	meta l4proto tcp tcp flags syn,ack / fin,syn,rst,urg,ack,psh accept
	meta l4proto tcp tcp flags fin,ack / fin,syn,rst,urg,ack,psh accept
	meta l4proto tcp tcp flags rst,ack / fin,syn,rst,urg,ack,psh accept
	meta l4proto tcp tcp flags syn,urg / fin,syn,rst,urg,ack,psh accept
	meta l4proto tcp tcp flags fin,ack,urg / fin,syn,rst,urg,ack,psh accept
	meta l4proto tcp tcp flags ack,urg / fin,syn,rst,urg,ack,psh accept
	meta l4proto tcp tcp flags rst,psh / fin,syn,rst,urg,ack,psh accept
	meta l4proto tcp tcp flags ack,psh / fin,syn,rst,urg,ack,psh accept
	meta l4proto tcp tcp flags fin,psh / fin,syn,rst,urg,ack,psh accept
	meta l4proto tcp tcp flags syn,ack,psh / fin,syn,rst,urg,ack,psh accept
	meta l4proto tcp tcp flags rst,ack,psh / fin,syn,rst,urg,ack,psh accept
	meta l4proto tcp tcp flags fin,ack,psh / fin,syn,rst,urg,ack,psh accept
	meta l4proto tcp counter drop
        return

		}

}

     table inet DDOS {
	chain drop_ddos {
		type filter hook prerouting priority -155;

		# CT INVALID
		ct state invalid counter drop

		udp sport 1-65535 ct state new jump udp_flood

		# TCP SYN (CT NEW)
		tcp flags & (fin|syn|rst|ack) != syn \
			ct state new \
			counter drop

		ct state established, related counter accept

        }
    }
TABLE

if [ $wan_input_drop_enable -ge 1 ]; then

nft -f - <<TABLE

table inet DDOS {
	chain drop_ddos {
		type filter hook prerouting priority -155;

		iifname { $wan_device } goto reject_drop

        }
    }
TABLE

fi

if [ $wireguard_input_drop_enable -ge 1 ]; then

nft -f - <<TABLE

table inet DDOS {
	chain drop_ddos {
		type filter hook prerouting priority -155;

		iifname { Wg0,Wg1,Wg2,Wg3,Wg4,Wg5,Wg6,Wg7,Wg8,Wg9 } goto reject_drop
      }
   }
TABLE

fi

if [ $bogon -ge 1 ]; then

nft -f - <<TABLE

		table inet DDOS {

  	  chain filter_ddos {
        	type filter hook prerouting priority -495;

		iifname { $wan_device } ip saddr { $forward_router } counter accept

		iifname { $wan_device } ip saddr { $bogon_adresses } counter drop

		iifname { $wan_device } ip6 saddr { $bogon_ipv6_adresses } counter drop

}

      }

		table inet DDOS {

  	  chain drop_forward {
        	type filter hook forward priority filter -5;

        ip daddr { $forward_router } counter accept

	oifname { $wan_device } ip daddr { $bogon_adresses } counter reject with icmp type host-unreachable

	oifname { $wan_device } ip6 daddr { $bogon_ipv6_adresses } counter reject with icmpv6 type no-route

           }

	chain drop_postrouting {
                 type filter hook postrouting priority filter +5;

         ip daddr { $forward_router } counter accept


         oifname { $wan_device } ip daddr { $bogon_adresses } counter drop

	oifname { $wan_device } ip6 daddr { $bogon_ipv6_adresses } counter drop

         }

}

TABLE

fi

$verbose

exit 0

