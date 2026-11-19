"""Unprivileged validation and API tests; these do not establish network isolation."""
import json
import pytest
from fastapi.testclient import TestClient
from backend.app.main import create_app
from network import client, store
from network.schema import DEFAULT_VLANS, validate_vlan, validate_vlans, validate_rule, validate_test, nft_ruleset
from network.topology import Lab

@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv('NETSCOPE_NETWORK_DB', str(tmp_path/'network.sqlite3'))
    def offline(*args, **kwargs):
        raise client.LabUnavailable('Test lab offline')
    monkeypatch.setattr(client, 'request', offline)
    with TestClient(create_app(tmp_path/'capture')) as app:
        yield app

@pytest.mark.parametrize('data', [
    {'id':0,'name':'Bad','subnet':'192.168.40.0/24'},
    {'id':4095,'name':'Bad','subnet':'192.168.40.0/24'},
    {'id':True,'name':'Bad','subnet':'192.168.40.0/24'},
    {'id':40,'name':'x;reboot','subnet':'192.168.40.0/24'},
    {'id':40,'name':'Bad','subnet':'8.8.8.0/24'},
    {'id':40,'name':'Bad','subnet':'127.0.0.0/24'},
    {'id':40,'name':'Bad','subnet':'192.168.40.5/24'},
])
def test_vlan_validation(data):
    with pytest.raises((ValueError, TypeError)):
        validate_vlan(data)

def test_overlap_and_required_departments():
    assert len(validate_vlans(DEFAULT_VLANS)) == 3
    with pytest.raises(ValueError, match='overlap'):
        validate_vlans(DEFAULT_VLANS + [{'id':40,'name':'Overlap','subnet':'192.168.10.0/25'}])
    with pytest.raises(ValueError, match='Keep example'):
        validate_vlans(DEFAULT_VLANS[:2])

@pytest.mark.parametrize('change', [
    {'source_vlan':10,'destination_vlan':10}, {'source_vlan':99},
    {'protocol':'tcp;reboot'}, {'action':'ACCEPT;reboot'},
    {'protocol':'icmp','destination_port':80}, {'protocol':'tcp','destination_port':65536},
    {'enabled':'yes'},
])
def test_rule_validation(change):
    with pytest.raises(ValueError):
        validate_rule({'id':'test','source_vlan':10,'destination_vlan':30,**change},{10,20,30})

def test_acl_compilation_and_precedence():
    allow=validate_rule({'id':'allow','source_vlan':10,'destination_vlan':30,'action':'allow'})
    deny=validate_rule({'id':'deny','source_vlan':10,'destination_vlan':30,'protocol':'icmp','action':'deny'})
    rules=nft_ruleset(DEFAULT_VLANS,[allow,deny],existing=True)
    assert rules.startswith('delete table inet netscope\n')
    assert 'policy drop' in rules
    assert rules.index('ip protocol icmp counter drop') < rules.index('ip daddr 192.168.30.0/24 counter accept')
    assert 'ct state established,related accept' in rules
    assert 'flush ruleset' not in rules
    assert 'policy accept' in nft_ruleset(DEFAULT_VLANS,[])

def test_host_allowlist():
    assert validate_test({'source':'eng1','destination':'eng2','count':3})['count']==3
    with pytest.raises(ValueError):
        validate_test({'source':'eng1;id','destination':'eng2'})

def test_offline_configuration_persistence_and_no_fabricated_tests(api, tmp_path):
    vlans=api.get('/api/vlans').json()
    assert [v['id'] for v in vlans] == [10,20,30]
    assert all(v['status']=='planned' for v in vlans)
    assert not api.get('/api/topology').json()['running']
    added=api.post('/api/vlans',json={'id':40,'name':'Operations','subnet':'192.168.40.0/24'})
    assert added.status_code==201 and added.json()['status']=='planned'
    assert api.post('/api/vlans',json={'id':40,'name':'Duplicate','subnet':'192.168.50.0/24'}).status_code==409
    rule=api.post('/api/segmentation/rules',json={'source_vlan':10,'destination_vlan':30,'action':'allow'}).json()
    assert rule['enabled'] and not rule['applied']
    assert api.patch('/api/segmentation/rules/'+rule['id'],json={'enabled':False}).json()['enabled'] is False
    assert api.get('/api/segmentation/rules').json()[0]['enabled'] is False
    assert api.post('/api/segmentation/test',json={'source':'eng1','destination':'eng2'}).status_code==503
    assert api.get('/api/segmentation/tests').json()==[]
    assert api.post('/api/topology/routing',json={'enabled':True}).status_code==503
    assert api.delete('/api/segmentation/rules/'+rule['id']).status_code==200
    assert api.get('/api/segmentation/rules').json()==[]
    assert store.get_vlans()[-1]['id']==40

def test_live_agent_confirmation_and_failure(api, monkeypatch):
    observed={'running':True,'available':True,'routing_enabled':False,'vlans':validate_vlans(DEFAULT_VLANS),'rules':[]}
    def agent(operation,payload=None):
        if operation=='configure': observed.update(payload)
        return observed
    monkeypatch.setattr(client,'request',agent)
    rule=api.post('/api/segmentation/rules',json={'source_vlan':10,'destination_vlan':30,'action':'allow'}).json()
    assert rule['applied']
    assert all(v['status']=='active' for v in api.get('/api/vlans').json())
    def fails(operation,payload=None):
        if operation=='configure': raise client.LabError('nft transaction rejected')
        return observed
    monkeypatch.setattr(client,'request',fails)
    assert api.delete('/api/segmentation/rules/'+rule['id']).status_code==502
    assert store.get_rules()[0]['id']==rule['id']

def test_observed_independent_rules_are_visible(api, monkeypatch):
    rule=validate_rule({'id':'operator-rule','source_vlan':20,'destination_vlan':10,'action':'deny'})
    monkeypatch.setattr(client,'request',lambda *a,**kw:{'running':True,'rules':[rule]})
    assert api.get('/api/segmentation/rules').json()==[{**rule,'applied':True}]

def test_configuration_failure_disables_forwarding(monkeypatch):
    lab=Lab();lab.router=object();lab.routing=True
    transitions=[]
    def routing(enabled):
        lab.routing=enabled;transitions.append(enabled)
    monkeypatch.setattr(lab,'set_routing',routing)
    def fails(*args,**kwargs):
        raise RuntimeError('kernel rejected VLAN configuration')
    monkeypatch.setattr('network.topology.execute',fails)
    with pytest.raises(RuntimeError): lab.configure(DEFAULT_VLANS,[])
    assert transitions==[False,False]
    assert lab.routing is False
