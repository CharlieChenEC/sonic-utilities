# definition of critical process for "show system status"
inside_process = [
    ('database', ['redis']),
    ('swss', ['orchagent', 'portsyncd', 'intfsyncd', 'neighsyncd', 'vlanmgrd', 'intfmgrd', 'portmgrd', 'buffermgrd' , 'vrfmgrd', 'nbrmgrd', 'vxlanmgrd', 'fdbsyncd']),
    ('syncd',  ['dsserve','syncd']),
    ('bgp', ['zebra', 'staticd', 'bgpd', 'fpmsyncd', 'bgpcfgd']),
    ('mgmt-framework', []),
    ('pmon',  ['ledd', 'xcvrd' , 'psud'] ),
    ('teamd', ['teammgrd', 'teamsyncd'] ),
    ('lldp',  ['lldpd' , 'lldp-syncd', 'lldpmgrd'] ),
]