# Installs, configures and enables UFW 
class ufw (

  Boolean $ipv6 = true,
  Boolean $purge_user_defined_rules = false,

) {
  if !($::kernel == 'Linux') {
    fail("${::kernel} is not supported")
  }

  # Variables for config file
  $_ipv6 = $ipv6 ? {
    false   => 'IPV6=no',
    default => 'IPV6=yes'
  }

  # Install package
  package { 'ufw': }

  # Deny all
  exec { 'ufw-deny':
    command => 'ufw default deny',
    unless  => 'ufw status verbose | grep -q "Default: deny (incoming)"',
    path    => $::path,
    require => Package['ufw']
  }

  # Enable UFW
  exec { 'ufw-enable':
    command => 'ufw --force enable',
    unless  => 'ufw status | grep -q "Status: active"',
    path    => $::path,
    require => Package['ufw']
  }

  # Disable IPv6
  file_line { 'ufw-ipv6':
    line    => $_ipv6,
    match   => '^IPV6=',
    path    => '/etc/default/ufw',
    notify  => Exec['reload_ufw'],
    require => Package['ufw']
  }

  exec { 'reload_ufw':
    command     => 'ufw --force enable && ufw reload',
    path        => $::path,
    require     => Package['ufw'],
    refreshonly => true
  }

  if $purge_user_defined_rules {
    file { '/etc/ufw/user.rules':
      ensure => present,
      source => 'puppet:///modules/ufw/default-user.rules'
    }

    file { '/etc/ufw/user6.rules':
      ensure => present,
      source => 'puppet:///modules/ufw/default-user6.rules'
    }
  }

  # Rules-Init:
  $user_rules_file = '/etc/ufw/before.rules'

  concat { $user_rules_file:
    ensure => present,
    warn   => true,
    mode   => '0640',
    notify => Exec['reload_ufw']
  }
  concat::fragment { "${user_rules_file}-header":
    target  => $user_rules_file,
    content => "
#
# rules.before
#
# Rules that should be run before the ufw command line added rules. Custom
# rules should be added to one of these chains:
#   ufw-before-input
#   ufw-before-output
#   ufw-before-forward
#

# Don't delete these required lines, otherwise there will be errors
*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
:ufw-before-forward - [0:0]
:ufw-not-local - [0:0]
# End required lines


# allow all on loopback
-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-output -o lo -j ACCEPT

# quickly process packets for which we already have a connection
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-forward -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# drop INVALID packets (logs these in loglevel medium and higher)
-A ufw-before-input -m conntrack --ctstate INVALID -j ufw-logging-deny
-A ufw-before-input -m conntrack --ctstate INVALID -j DROP

# ok icmp codes for INPUT
-A ufw-before-input -p icmp --icmp-type destination-unreachable -j ACCEPT
-A ufw-before-input -p icmp --icmp-type time-exceeded -j ACCEPT
-A ufw-before-input -p icmp --icmp-type parameter-problem -j ACCEPT
-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT

# ok icmp code for FORWARD
-A ufw-before-forward -p icmp --icmp-type destination-unreachable -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type time-exceeded -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type parameter-problem -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type echo-request -j ACCEPT

# allow dhcp client to work
-A ufw-before-input -p udp --sport 67 --dport 68 -j ACCEPT

#
# ufw-not-local
#
-A ufw-before-input -j ufw-not-local

# if LOCAL, RETURN
-A ufw-not-local -m addrtype --dst-type LOCAL -j RETURN

# if MULTICAST, RETURN
-A ufw-not-local -m addrtype --dst-type MULTICAST -j RETURN

# if BROADCAST, RETURN
-A ufw-not-local -m addrtype --dst-type BROADCAST -j RETURN

# all other non-local packets are dropped
-A ufw-not-local -m limit --limit 3/min --limit-burst 10 -j ufw-logging-deny
-A ufw-not-local -j DROP

# allow MULTICAST mDNS for service discovery (be sure the MULTICAST line above
# is uncommented)
-A ufw-before-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT

# allow MULTICAST UPnP for service discovery (be sure the MULTICAST line above
# is uncommented)
-A ufw-before-input -p udp -d 239.255.255.250 --dport 1900 -j ACCEPT

### CUSTOM RULES ###
",
    order   => '0'
  }
  concat::fragment { "${user_rules_file}-footer":
    target  => $user_rules_file,
    content => "
### END CUSTOM RULES ###

# don't delete the 'COMMIT' line or these rules won't be processed
COMMIT
",
    order   => '99999'
  }

  if ($ipv6) {
    $user6_rules_file = '/etc/ufw/before6.rules'

    concat { $user6_rules_file:
      ensure => present,
      warn   => true,
      mode   => '0640',
      notify => Exec['reload_ufw']
    }
    concat::fragment { "${user6_rules_file}-header":
      target  => $user6_rules_file,
      content => "#
# rules.before
#
# Rules that should be run before the ufw command line added rules. Custom
# rules should be added to one of these chains:
#   ufw6-before-input
#   ufw6-before-output
#   ufw6-before-forward
#

# Don't delete these required lines, otherwise there will be errors
*filter
:ufw6-before-input - [0:0]
:ufw6-before-output - [0:0]
:ufw6-before-forward - [0:0]
# End required lines


# allow all on loopback
-A ufw6-before-input -i lo -j ACCEPT
-A ufw6-before-output -o lo -j ACCEPT

# drop packets with RH0 headers
-A ufw6-before-input -m rt --rt-type 0 -j DROP
-A ufw6-before-forward -m rt --rt-type 0 -j DROP
-A ufw6-before-output -m rt --rt-type 0 -j DROP

# quickly process packets for which we already have a connection
-A ufw6-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw6-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw6-before-forward -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# multicast ping replies are part of the ok icmp codes for INPUT (rfc4890,
# 4.4.1 and 4.4.2), but don't have an associated connection and are otherwise
# be marked INVALID, so allow here instead.
-A ufw6-before-input -p icmpv6 --icmpv6-type echo-reply -j ACCEPT

# drop INVALID packets (logs these in loglevel medium and higher)
-A ufw6-before-input -m conntrack --ctstate INVALID -j ufw6-logging-deny
-A ufw6-before-input -m conntrack --ctstate INVALID -j DROP

# ok icmp codes for INPUT (rfc4890, 4.4.1 and 4.4.2)
-A ufw6-before-input -p icmpv6 --icmpv6-type destination-unreachable -j ACCEPT
-A ufw6-before-input -p icmpv6 --icmpv6-type packet-too-big -j ACCEPT
# codes 0 and 1
-A ufw6-before-input -p icmpv6 --icmpv6-type time-exceeded -j ACCEPT
# codes 0-2 (echo-reply needs to be before INVALID, see above)
-A ufw6-before-input -p icmpv6 --icmpv6-type parameter-problem -j ACCEPT
-A ufw6-before-input -p icmpv6 --icmpv6-type echo-request -j ACCEPT
-A ufw6-before-input -p icmpv6 --icmpv6-type router-solicitation -m hl --hl-eq 255 -j ACCEPT
-A ufw6-before-input -p icmpv6 --icmpv6-type router-advertisement -m hl --hl-eq 255 -j ACCEPT
-A ufw6-before-input -p icmpv6 --icmpv6-type neighbor-solicitation -m hl --hl-eq 255 -j ACCEPT
-A ufw6-before-input -p icmpv6 --icmpv6-type neighbor-advertisement -m hl --hl-eq 255 -j ACCEPT
# IND solicitation
-A ufw6-before-input -p icmpv6 --icmpv6-type 141 -m hl --hl-eq 255 -j ACCEPT
# IND advertisement
-A ufw6-before-input -p icmpv6 --icmpv6-type 142 -m hl --hl-eq 255 -j ACCEPT
# MLD query
-A ufw6-before-input -p icmpv6 --icmpv6-type 130 -s fe80::/10 -j ACCEPT
# MLD report
-A ufw6-before-input -p icmpv6 --icmpv6-type 131 -s fe80::/10 -j ACCEPT
# MLD done
-A ufw6-before-input -p icmpv6 --icmpv6-type 132 -s fe80::/10 -j ACCEPT
# MLD report v2
-A ufw6-before-input -p icmpv6 --icmpv6-type 143 -s fe80::/10 -j ACCEPT
# SEND certificate path solicitation
-A ufw6-before-input -p icmpv6 --icmpv6-type 148 -m hl --hl-eq 255 -j ACCEPT
# SEND certificate path advertisement
-A ufw6-before-input -p icmpv6 --icmpv6-type 149 -m hl --hl-eq 255 -j ACCEPT
# MR advertisement
-A ufw6-before-input -p icmpv6 --icmpv6-type 151 -s fe80::/10 -m hl --hl-eq 1 -j ACCEPT
# MR solicitation
-A ufw6-before-input -p icmpv6 --icmpv6-type 152 -s fe80::/10 -m hl --hl-eq 1 -j ACCEPT
# MR termination
-A ufw6-before-input -p icmpv6 --icmpv6-type 153 -s fe80::/10 -m hl --hl-eq 1 -j ACCEPT

# ok icmp codes for OUTPUT (rfc4890, 4.4.1 and 4.4.2)
-A ufw6-before-output -p icmpv6 --icmpv6-type destination-unreachable -j ACCEPT
-A ufw6-before-output -p icmpv6 --icmpv6-type packet-too-big -j ACCEPT
# codes 0 and 1
-A ufw6-before-output -p icmpv6 --icmpv6-type time-exceeded -j ACCEPT
# codes 0-2
-A ufw6-before-output -p icmpv6 --icmpv6-type parameter-problem -j ACCEPT
-A ufw6-before-output -p icmpv6 --icmpv6-type echo-request -j ACCEPT
-A ufw6-before-output -p icmpv6 --icmpv6-type echo-reply -j ACCEPT
-A ufw6-before-output -p icmpv6 --icmpv6-type router-solicitation -m hl --hl-eq 255 -j ACCEPT
-A ufw6-before-output -p icmpv6 --icmpv6-type neighbor-advertisement -m hl --hl-eq 255 -j ACCEPT
-A ufw6-before-output -p icmpv6 --icmpv6-type neighbor-solicitation -m hl --hl-eq 255 -j ACCEPT
-A ufw6-before-output -p icmpv6 --icmpv6-type router-advertisement -m hl --hl-eq 255 -j ACCEPT
# IND solicitation
-A ufw6-before-output -p icmpv6 --icmpv6-type 141 -m hl --hl-eq 255 -j ACCEPT
# IND advertisement
-A ufw6-before-output -p icmpv6 --icmpv6-type 142 -m hl --hl-eq 255 -j ACCEPT
# MLD query
-A ufw6-before-output -p icmpv6 --icmpv6-type 130 -s fe80::/10 -j ACCEPT
# MLD report
-A ufw6-before-output -p icmpv6 --icmpv6-type 131 -s fe80::/10 -j ACCEPT
# MLD done
-A ufw6-before-output -p icmpv6 --icmpv6-type 132 -s fe80::/10 -j ACCEPT
# MLD report v2
-A ufw6-before-output -p icmpv6 --icmpv6-type 143 -s fe80::/10 -j ACCEPT
# SEND certificate path solicitation
-A ufw6-before-output -p icmpv6 --icmpv6-type 148 -m hl --hl-eq 255 -j ACCEPT
# SEND certificate path advertisement
-A ufw6-before-output -p icmpv6 --icmpv6-type 149 -m hl --hl-eq 255 -j ACCEPT
# MR advertisement
-A ufw6-before-output -p icmpv6 --icmpv6-type 151 -s fe80::/10 -m hl --hl-eq 1 -j ACCEPT
# MR solicitation
-A ufw6-before-output -p icmpv6 --icmpv6-type 152 -s fe80::/10 -m hl --hl-eq 1 -j ACCEPT
# MR termination
-A ufw6-before-output -p icmpv6 --icmpv6-type 153 -s fe80::/10 -m hl --hl-eq 1 -j ACCEPT

# ok icmp codes for FORWARD (rfc4890, 4.3.1)
-A ufw6-before-forward -p icmpv6 --icmpv6-type destination-unreachable -j ACCEPT
-A ufw6-before-forward -p icmpv6 --icmpv6-type packet-too-big -j ACCEPT
# codes 0 and 1
-A ufw6-before-forward -p icmpv6 --icmpv6-type time-exceeded -j ACCEPT
# codes 0-2
-A ufw6-before-forward -p icmpv6 --icmpv6-type parameter-problem -j ACCEPT
-A ufw6-before-forward -p icmpv6 --icmpv6-type echo-request -j ACCEPT
-A ufw6-before-forward -p icmpv6 --icmpv6-type echo-reply -j ACCEPT
# ok icmp codes for FORWARD (rfc4890, 4.3.2)
# Home Agent Address Discovery Reques
-A ufw6-before-input -p icmpv6 --icmpv6-type 144 -j ACCEPT
# Home Agent Address Discovery Reply
-A ufw6-before-input -p icmpv6 --icmpv6-type 145 -j ACCEPT
# Mobile Prefix Solicitation
-A ufw6-before-input -p icmpv6 --icmpv6-type 146 -j ACCEPT
# Mobile Prefix Advertisement
-A ufw6-before-input -p icmpv6 --icmpv6-type 147 -j ACCEPT

# allow dhcp client to work
-A ufw6-before-input -p udp -s fe80::/10 --sport 547 -d fe80::/10 --dport 546 -j ACCEPT

# allow MULTICAST mDNS for service discovery
-A ufw6-before-input -p udp -d ff02::fb --dport 5353 -j ACCEPT

# allow MULTICAST UPnP for service discovery
-A ufw6-before-input -p udp -d ff02::f --dport 1900 -j ACCEPT

### CUSTOM RULES ###
",
      order   => '0'
    }
    concat::fragment { "${user6_rules_file}-footer":
      target  => $user6_rules_file,
      content => "
### END CUSTOM RULES ###

# don't delete the 'COMMIT' line or these rules won't be processed
COMMIT
",
      order   => '99999'
    }
  }

}
