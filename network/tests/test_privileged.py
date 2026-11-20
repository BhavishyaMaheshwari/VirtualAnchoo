"""Actual isolated Linux lab tests. Every reachability assertion uses real ping.

Run only on a dedicated Ubuntu VM, with no other VirtualAnchoo lab running:
  sudo env VIRTUALANCHOO_RUN_NETWORK_TESTS=1 .venv/bin/python -m pytest network/tests/test_privileged.py -v
Mininet's system package must be visible to the interpreter (see setup.md).
"""
import importlib.util
import os
import shutil
import socket
import sys
import pytest
from network.topology import Lab
from network.schema import validate_rule, HOSTS, TRUNK

@pytest.fixture(scope='module')
def lab():
    if os.getenv('VIRTUALANCHOO_RUN_NETWORK_TESTS')!='1':
        pytest.skip('Set VIRTUALANCHOO_RUN_NETWORK_TESTS=1 on an authorized isolated Linux VM')
    if sys.platform!='linux' or os.geteuid()!=0:
        pytest.skip('Requires Linux root and network administration capabilities')
    missing=[name for name in ['mnexec','ovs-vsctl','nft','ip','ping'] if not shutil.which(name)]
    if missing or importlib.util.find_spec('mininet') is None:
        pytest.skip('Missing Mininet/OVS/nftables dependencies: '+', '.join(missing))
    state=Lab()
    state.start()
    try: yield state
    finally: state.stop()

def reset(lab, routing=False, rules=None):
    lab.set_routing(False)
    lab.configure(lab.vlans,rules or [])
    lab.set_routing(routing)

@pytest.mark.privileged
@pytest.mark.integration
def test_actual_ovs_access_trunk_and_dot1q(lab):
    observed=lab.inspect()
    rows=[dict(zip(observed['ovs_ports']['headings'],r)) for r in observed['ovs_ports']['data']]
    for host in HOSTS.values():
        port=next(r for r in rows if r['name']==host['port'])
        assert port['vlan_mode']=='access'
        assert port['tag']==host['vlan_id']
    trunk=next(r for r in rows if r['name']==TRUNK)
    assert trunk['vlan_mode']=='trunk'
    assert set(trunk['trunks'][1])=={10,20,30}
    names={i['ifname'] for i in observed['router_interfaces']}
    assert {'ns-r1-eth0.10','ns-r1-eth0.20','ns-r1-eth0.30'} <= names

@pytest.mark.privileged
@pytest.mark.integration
def test_actual_same_vlan_reachability(lab):
    reset(lab)
    assert lab.test({'source':'eng1','destination':'eng2','count':3})['success']

@pytest.mark.privileged
@pytest.mark.integration
def test_actual_inter_vlan_isolation(lab):
    reset(lab)
    result=lab.test({'source':'eng1','destination':'adm1','count':3})
    assert result['exit_code']==1 and result['received']==0

@pytest.mark.privileged
@pytest.mark.integration
def test_actual_inter_vlan_routing(lab):
    reset(lab,True)
    assert lab.test({'source':'eng1','destination':'adm1','count':3})['success']

@pytest.mark.privileged
@pytest.mark.integration
def test_actual_acl_allow_deny_and_icmp(lab):
    rules=[validate_rule({'id':'eng-adm','source_vlan':10,'destination_vlan':30,'action':'allow'}),
           validate_rule({'id':'fin-eng','source_vlan':20,'destination_vlan':10,'action':'deny'}),
           validate_rule({'id':'adm-fin','source_vlan':30,'destination_vlan':20,'action':'allow'})]
    reset(lab,True,rules)
    assert lab.test({'source':'eng1','destination':'adm1','count':3})['success']
    assert not lab.test({'source':'fin1','destination':'eng1','count':3})['success']
    assert lab.test({'source':'adm1','destination':'fin1','count':3})['success']
    rules.append(validate_rule({'id':'icmp-deny','source_vlan':10,'destination_vlan':30,'protocol':'icmp','action':'deny'}))
    reset(lab,True,rules)
    assert not lab.test({'source':'eng2','destination':'adm2','count':3})['success']
