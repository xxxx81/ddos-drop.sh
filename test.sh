#!/bin/sh
#***********config section***********************************
wan_device=""
forward_router="0.0.0.0"
forward_router_IpV6="0000:0000:0000:0000:0000:0000:0000:0000"
wan_input_drop_enable="0"
wireguard_input_drop_enable="0" 
tcp_limit_enable="0"
udp_limit_enable="0"
icmp_limit_enable="0"
arp_limit_enable="0"
bogon="0"

#***********parameter section********************************
tcp_limit="50"
udp_limit="100"
icmp_limit="15"
arp_limit="1"
drop_time="1h"

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
#***********parameter section********************************

verbose=false

if [ -z "$wan_device" ]; then

wan_device=$(uci get network.wan.device)

fi

nft list ruleset | grep -q 'DDOS_Protection' && nft delete table inet DDOS_Protection
nft list ruleset | grep -q 'ARP' && nft delete table arp ARP

if [ $tcp_limit_enable -ge 1 ]; then

nft -f - <<TABLE

table inet DDOS_Protection {

        set enemies4 {
                  type ipv4_addr
                  flags dynamic,timeout
                 timeout $drop_time
         }

         set enemies6 {
                 type ipv6_addr
                 flags dynamic,timeout
                 timeout $drop_time

	}
 
    chain tcp_limit {               
             limit rate $tcp_limit/second burst 1 packets accept
             limit rate over $tcp_limit/second burst 1 packets log prefix "Possible_tcp_attack (drop $drop_time): " update @enemies6 { ip6  saddr } ct event set destroy counter drop
             limit rate over $tcp_limit/second burst 1 packets log prefix "Possible_tcp_attack (drop $drop_time): " update @enemies4 { ip saddr } ct event set destroy counter drop

    }

}

TABLE

else

nft -f - <<TABLE

table inet DDOS_Protection {

        set enemies4 {
                  type ipv4_addr
                  flags dynamic,timeout
                 timeout $drop_time
         }

         set enemies6 {
                 type ipv6_addr
                 flags dynamic,timeout
                 timeout $drop_time

	}


    chain tcp_limit {

                return

    }

}

TABLE

fi;               

if [ $udp_limit_enable -ge 1 ]; then

nft -f - <<TABLE

table inet DDOS_Protection {

    chain udp_limit {
               limit rate $udp_limit/second burst 1 packets accept
               limit rate over $udp_limit/second burst 1 packets log prefix "Possible_udp_attack (drop $drop_time): " update @enemies4 { ip  saddr } ct event set destroy counter drop
               limit rate over $udp_limit/second burst 1 packets log prefix "Possible_udp_attack (drop $drop_time): " update @enemies6 { ip6 saddr } ct event set destroy counter drop
    
    }

}

TABLE

else

nft -f - <<TABLE

table inet DDOS_Protection {

    chain udp_limit {

                return

    }

}

TABLE

fi;               

if [ $icmp_limit_enable -ge 1 ]; then

nft -f - <<TABLE

table inet DDOS_Protection {

    chain icmp_limit {

		       limit rate $icmp_limit/second burst 1 packets return
		       counter drop

    }

}

TABLE

else

nft -f - <<TABLE

table inet DDOS_Protection {

    chain icmp_limit {

                return

   }

}

TABLE

fi

nft -f - <<TABLE

table inet DDOS_Protection {
          
    chain input_drop { type filter hook prerouting priority -500;
    ip  saddr @enemies4  update @enemies4 { ip  saddr }  counter  drop
    ip6 saddr @enemies6  update @enemies6 { ip6 saddr }  counter  drop

    }

    chain flags_input {
       
	ip protocol icmp icmp type {echo-reply, destination-unreachable, source-quench, redirect, echo-request, time-exceeded, parameter-problem, timestamp-request, timestamp-reply, info-request, info-reply, \
	
    address-mask-request, address-mask-reply, router-advertisement, router-solicitation} jump icmp_limit

	ip protocol icmpv6 icmpv6 type {destination-unreachable, packet-too-big, time-exceeded, echo-request, echo-reply, mld-listener-query, mld-listener-report, mld-listener-reduction, nd-router-solicit, \
	
    nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect, parameter-problem, router-renumbering} jump icmp_limit

    ip frag-off & 0x1fff != 0 counter drop

    ip saddr { $forward_router } counter accept

    ip6 saddr { $forward_router_IpV6 } counter accept

    udp dport 1-65535 ct state new jump udp_limit

    meta l4proto tcp tcp flags syn tcp option maxseg size 1-535 ct state new jump tcp_limit

    meta l4proto tcp tcp flags syn tcp option maxseg size 1-535 drop
	
    meta l4proto tcp tcp flags syn / fin,syn,rst,urg,ack,psh ct state new goto tcp_limit   

    meta l4proto tcp tcp flags fin / fin,syn,rst,urg,ack,psh ct state new goto tcp_limit    
	
    meta l4proto tcp tcp flags rst / fin,syn,rst,urg,ack,psh ct state new goto tcp_limit   
	
    meta l4proto tcp tcp flags ack / fin,syn,rst,urg,ack,psh ct state new goto tcp_limit
	
    meta l4proto tcp tcp flags syn,ack / fin,syn,rst,urg,ack,psh ct state new goto tcp_limit
	
    meta l4proto tcp tcp flags fin,ack / fin,syn,rst,urg,ack,psh ct state new goto tcp_limit
	
    meta l4proto tcp tcp flags rst,ack / fin,syn,rst,urg,ack,psh ct state new goto tcp_limit    
	
    meta l4proto tcp tcp flags ack,psh / fin,syn,rst,urg,ack,psh ct state new goto tcp_limit
	
    meta l4proto tcp tcp flags fin,psh / fin,syn,rst,urg,ack,psh ct state new goto tcp_limit
	
    meta l4proto tcp tcp flags ack,fin,psh / fin,syn,rst,urg,ack,psh ct state new goto tcp_limit
	
    meta l4proto tcp ct state new jump tcp_limit

    meta l4proto tcp counter log prefix "Invalid flags: " drop

    return

	}

    chain input_chain {
		type filter hook prerouting priority -190;

	ct state established accept

    iifname { $wan_device } jump flags_input

	tcp flags & (fin|syn|rst|ack) != syn ct state new counter drop

            }

}

TABLE

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

if [ $wan_input_drop_enable -ge 1 ]; then

nft -f - <<TABLE

table inet DDOS_Protection {
	chain input_chain {
		
		iifname { $wan_device } ct event set destroy counter drop

        }
    }
TABLE

fi

if [ $wireguard_input_drop_enable -ge 1 ]; then

nft -f - <<TABLE

table inet DDOS_Protection {
	chain input_chain {
		
		iifname { Wg0,Wg1,Wg2,Wg3,Wg4,Wg5,Wg6,Wg7,Wg8,Wg9 } ct event set destroy counter drop

      }
   }
TABLE

fi

if [ $bogon -ge 1 ]; then

nft -f - <<TABLE

	table inet DDOS_Protection {

  	  chain input_drop {
        	
		iifname { $wan_device } ip saddr { $forward_router } counter accept

		iifname { $wan_device } ip6 saddr { $forward_router_IpV6 } counter accept

		iifname { $wan_device } ip saddr { $bogon_adresses } counter drop

		iifname { $wan_device } ip6 saddr { $bogon_ipv6_adresses } counter drop

    }

  	  chain drop_forward {
        	type filter hook forward priority filter -5;

    ip daddr { $forward_router } counter accept

    ip6 daddr { $forward_router_IpV6 } counter accept

	oifname { $wan_device } ip daddr { $bogon_adresses } counter reject with icmp type host-unreachable

	oifname { $wan_device } ip6 daddr { $bogon_ipv6_adresses } counter reject with icmpv6 type no-route

           }

	chain drop_postrouting {
                 type filter hook postrouting priority filter +5;

    ip daddr { $forward_router } counter accept

    ip6 daddr { $forward_router_IpV6 } counter accept

    oifname { $wan_device } ip daddr { $bogon_adresses } counter drop

	oifname { $wan_device } ip6 daddr { $bogon_ipv6_adresses } counter drop

         }

}

TABLE

fi


$verbose

exit 0

