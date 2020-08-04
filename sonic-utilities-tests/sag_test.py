import sys
import os
import pytest
import click
from click.testing import CliRunner

test_path = os.path.dirname(os.path.abspath(__file__))
modules_path = os.path.dirname(test_path)
scripts_path = os.path.join(modules_path, "scripts")
sys.path.insert(0, test_path)
sys.path.insert(0, modules_path)

from swsssdk import SonicV2Connector
import mock_tables.dbconnector
import show.main as show

runner = CliRunner()

class TestSagShow(object) :

    def test_show(self) :
        runner = CliRunner()
        result = runner.invoke(show.cli.commands["sag"], [])
        print("\n"+result.output)
        expected =["Static Anycast Gateway Information",
        "",
        "MacAddress         IPv4    IPv6",
        "-----------------  ------  -------",
        "00-05-5D-E8-0F-A3  enable  disable"]
        for line in expected:
            assert line in result.output

    def test_show_ip(self) :
        runner = CliRunner()
        result = runner.invoke(show.cli.commands["sag"].commands["ip"], [])
        print("\n"+result.output)
        expected =["Vlan Interface Name    IPv4 address/mask",
        "---------------------  -------------------",
        "Vlan1000               192.168.0.1/24",
        "                       192.168.0.2/24"]
        for line in expected:
            assert line in result.output

    def test_show_ipv6(self) :
        runner = CliRunner()
        result = runner.invoke(show.cli.commands["sag"].commands["ipv6"], [])
        print("\n"+result.output)
        expected =["Vlan Interface Name    IPv6 address/mask",
        "---------------------  -------------------",
        "Vlan1000               2001:648:2000::/128"]
        for line in expected:
            assert line in result.output

class TestSagConfig(object) :
    ORIGIN_MAC_ADDRESS = "00-05-5D-E8-0F-A3"
    TMP_MAC_ADDRESS = "09-54-11-2d-c5-22"
    MAC_TABLE_NAME = "SAG_GLOBAL"
    IP_TABLE_NAME = "SAG"

    @pytest.fixture(scope = 'class')
    def basic_setup(self,get_cmd_module):
        (config, show, db) = get_cmd_module
        config_db = db['config_db']
        ctx_obj = {'db': config_db}
        yield config,config_db,ctx_obj

    @pytest.fixture()
    def ip_interface_setup(self,get_cmd_module) :
        (config, show, db) = get_cmd_module
        config_db = db['config_db']
        state_db = db['state_db']
        ctx_obj = {'config_db': config_db,'state_db':state_db}
        runner = CliRunner()
        state_db.set_entry('VLAN_TABLE', 'Vlan1000', {'state': 'ok'})
        yield config,config_db,ctx_obj

    def set_mac_address(self,oper,address,basic_setup) :
        config,_,ctx_obj = basic_setup
        if oper =='add' :
            result = runner.invoke(config.config.commands["sag"].commands["mac_address"].commands["add"],[address],obj = ctx_obj)
        elif oper == 'del' :
            result = runner.invoke(config.config.commands["sag"].commands["mac_address"].commands["del"],[address],obj = ctx_obj)

        if result.exit_code == 0 :
            return True
        else :return False

    def check_mac_address(self,oper,address,basic_setup) :
        _,config_db,_ = basic_setup
        if oper =='add' :
            tbl = config_db.get_table(self.MAC_TABLE_NAME)
            keys = tbl.keys()
            assert len(keys) == 1
            assert keys[0] == 'IP'
            entry = config_db.get_entry(self.MAC_TABLE_NAME, 'IP')
            assert entry != {}
            assert entry['gwmac'] == address
        elif oper == 'del' :
            tbl = config_db.get_table(self.MAC_TABLE_NAME)
            assert tbl =={}

    def set_ip_knob(self,ip,oper,basic_setup) :
        config,_,ctx_obj = basic_setup
        result = runner.invoke(config.config.commands["sag"].commands[ip].commands[oper],[],obj = ctx_obj)
        if result.exit_code == 0 :
            return True
        else :return False

    def check_ip_knob(self,ip,oper,basic_setup) :
        _,config_db,_ = basic_setup
        tbl = config_db.get_table(self.MAC_TABLE_NAME)
        keys = tbl.keys()
        assert len(keys) == 1
        assert keys[0] == 'IP'
        entry = config_db.get_entry(self.MAC_TABLE_NAME, 'IP')
        assert entry != {}
        assert entry[ip] == oper

    def set_interface_ip(self,oper,vlan,ip,ip_interface_setup) :
        config,_,ctx_obj= ip_interface_setup
        result = runner.invoke(config.config.commands["interface"].commands["sag"].commands["ip"].commands[oper], [vlan,ip], obj = ctx_obj)
        if result.exit_code == 0 :
            return True
        else : return False

    def check_interface_ip(self,vlan,ip_type,data,ip_interface_setup) :
        _,config_db,_ = ip_interface_setup
        entry = config_db.get_entry(self.IP_TABLE_NAME, vlan+'|'+ip_type)
        if data == 'NULL' :
             assert entry == {}
        else :
            assert entry != {}
            assert entry['gwip'] == data

    def test_config_mac_add_del(self,basic_setup) :
        assert self.set_mac_address('add',self.TMP_MAC_ADDRESS,basic_setup) == True
        self.check_mac_address('add',self.TMP_MAC_ADDRESS,basic_setup)

        assert self.set_mac_address('del',self.TMP_MAC_ADDRESS,basic_setup) == True
        self.check_mac_address('del',self.TMP_MAC_ADDRESS,basic_setup)

        assert self.set_mac_address('add',self.ORIGIN_MAC_ADDRESS,basic_setup) == True
        self.check_mac_address('add',self.ORIGIN_MAC_ADDRESS,basic_setup)

    def test_config_ipv4_enable_disable(self, basic_setup) :
        assert self.set_ip_knob('ipv4','disable',basic_setup) == True
        self.check_ip_knob('IPv4','disable',basic_setup)

        assert self.set_ip_knob('ipv4','enable',basic_setup) == True
        self.check_ip_knob('IPv4','enable',basic_setup)

    def test_config_ipv6_enable_disable(self, basic_setup) :
        assert self.set_ip_knob('ipv6','enable',basic_setup) == True
        self.check_ip_knob('IPv6','enable',basic_setup)

        assert self.set_ip_knob('ipv6','disable',basic_setup) == True
        self.check_ip_knob('IPv6','disable',basic_setup)

    def test_config_interface_ip_add_del(self, ip_interface_setup) :
        assert self.set_interface_ip('add','Vlan999','192.0.0.3/24',ip_interface_setup) == False
        assert self.set_interface_ip('add','Vlan999','::1/128',ip_interface_setup) == False
        assert self.set_interface_ip('del','Vlan999','192.0.0.1/24',ip_interface_setup) == False
        assert self.set_interface_ip('del','Vlan999','2001:648:2000::/128',ip_interface_setup) == False

        assert self.set_interface_ip('del','Vlan1000','192.168.0.1/24',ip_interface_setup) == True
        self.check_interface_ip('Vlan1000','IPv4',['192.168.0.2/24'],ip_interface_setup)

        assert self.set_interface_ip('del','Vlan1000','192.168.0.2/24',ip_interface_setup) == True
        self.check_interface_ip('Vlan1000','IPv4','NULL',ip_interface_setup)

        assert self.set_interface_ip('add','Vlan1000','192.168.0.1/24',ip_interface_setup) == True
        self.check_interface_ip('Vlan1000','IPv4',['192.168.0.1/24'],ip_interface_setup)

        assert self.set_interface_ip('add','Vlan1000','192.168.0.2/24',ip_interface_setup) == True
        self.check_interface_ip('Vlan1000','IPv4',['192.168.0.1/24','192.168.0.2/24'],ip_interface_setup)


        assert self.set_interface_ip('del','Vlan1000','2001:648:2000::/128',ip_interface_setup) == True
        self.check_interface_ip('Vlan1000','IPv6','NULL',ip_interface_setup)

        assert self.set_interface_ip('add','Vlan1000','2001:648:2000::/128',ip_interface_setup) == True
        self.check_interface_ip('Vlan1000','IPv6',['2001:648:2000::/128'],ip_interface_setup)
