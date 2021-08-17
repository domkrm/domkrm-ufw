# Creates a new allow rule in UFW
define ufw::allow (

  String $port,
  Enum['tcp', 'udp'] $proto = 'tcp',
  String $interface = '',
  String $from = '',
  Enum['present', 'absent'] $ensure = 'present'

) {

  if !defined(Class['ufw']) {
    fail('You must include the UFW base class first')
  }

  $_interface = $interface ? {
    ''      => '',
    default => "_${interface}"
  }
  $_interface_cmd = $interface ? {
    ''      => '',
    default => " -i ${interface}"
  }

  $_from = $from ? {
    ''      => '0.0.0.0/0',
    any     => '0.0.0.0/0',
    default => $from
  }
  $_from_cmd = $from ? {
    ''      => '',
    'any'   => '',
    default => " -s ${from}"
  }

  if $ensure == 'present' {

    concat::fragment { "${ufw::user_rules_file}-${name}":
      target  => $ufw::user_rules_file,
      content => "
### tuple ### allow ${proto} ${port} 0.0.0.0/0 any ${_from} in${_interface}
-A ufw-user-input${_interface_cmd} -p ${proto} --dport ${port}${_from_cmd} -j ACCEPT",
      order   => $port
    }

    if $ufw::ipv6 and $from == '' {

      # Ignore 'from' option on ipv6
      concat::fragment { "${ufw::user6_rules_file}-${name}":
        target  => $ufw::user6_rules_file,
        content => "
### tuple ### allow ${proto} ${port} ::/0 any ::/0 in${_interface}
-A ufw6-user-input${_interface_cmd} -p ${proto} --dport ${port} -j ACCEPT

  ",
        order   => $port
      }

    }

  }

}
