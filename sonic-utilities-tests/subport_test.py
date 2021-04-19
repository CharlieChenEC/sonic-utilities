import pytest
import platform
from distutils.version import StrictVersion
from click.testing import CliRunner
from natsort import natsorted
from mock import patch

class TestSubport(object):
    @classmethod
    def setup_class(cls):
        cls.runner = CliRunner()
        cls.config_db_tables = {}
        cls.app_db_tables = {}
        cls.state_db_tables = {}

    @pytest.fixture(scope='class', autouse=True)
    def basic_suite(self, get_cmd_module):
        (config, show, db) = get_cmd_module
        yield (config, show, db)

    def is_subport_exist(self, db, key):
        tbl = db.get_table("VLAN_SUB_INTERFACE")
        fvs = tbl.get(key)
        return True if fvs != None else False

    def check_subport_admin_status(self, db, key, status):
        entry = db.get_entry("VLAN_SUB_INTERFACE", key)
        return True if entry['admin_status'] == status else False

    def get_err_str(self, result_output):
        return result_output.split('Error: ')[1].strip('\n')

    @patch('config.main.run_command')
    @pytest.mark.parametrize("oper, test_args", [
        ("add", ["Ethernet4.10", "192.169.1.1/24"]),
        ("add", ["Ethernet4.20", "192.169.2.1/24"]),
        ("add", ["Ethernet8.20", "192.169.3.1/24"]),
        ("remove", ["Ethernet4.10", "192.169.1.1/24"]),
        ("remove", ["Ethernet4.20", "192.169.2.1/24"]),
        ("remove", ["Ethernet8.20", "192.169.3.1/24"]),
        ("add", ["Ethernet4.10", "3fff::1/64"]),
        ("remove", ["Ethernet4.10", "3fff::1/64"])
    ])
    def test_subport_ipv4_ipv6_add_del(self, mock_run, basic_suite, oper, test_args) :
        (config, show, db) = basic_suite
        config_db = db['config_db']
        ctx_obj = {'config_db': config_db}

        result = self.runner.invoke(config.config.commands['interface'].commands['ip'].commands[oper], test_args, obj=ctx_obj)
        assert result.exit_code == 0
        if oper == "add":
            assert True == self.is_subport_exist(config_db, test_args[0])
        else:
            assert False == self.is_subport_exist(config_db, test_args[0])

    @patch('config.main.run_command')
    def test_subport_admin_status_change(self, mock_run, basic_suite) :
        (config, show, db) = basic_suite
        config_db = db['config_db']
        ctx_obj = {'config_db': config_db}

        intf_name = "Ethernet0.10"
        ip_addr = "192.169.1.1/24"
        result = self.runner.invoke(config.config.commands['interface'].commands['ip'].commands['add'], [intf_name, ip_addr], obj=ctx_obj)
        assert result.exit_code == 0
        assert True == self.is_subport_exist(config_db, intf_name)
        assert True == self.check_subport_admin_status(config_db, intf_name, 'up')

        result = self.runner.invoke(config.config.commands['interface'].commands['shutdown'], [intf_name], obj=ctx_obj)
        assert result.exit_code == 0
        assert True == self.check_subport_admin_status(config_db, intf_name, 'down')
        result = self.runner.invoke(config.config.commands['interface'].commands['ip'].commands['remove'], [intf_name, ip_addr], obj=ctx_obj)
        assert result.exit_code == 0

    @patch('config.main.run_command')
    def test_subport_validate_intf_name(self, mock_run, basic_suite):
        (config, show, db) = basic_suite
        ctx_obj = {'config_db': db['config_db']}

        intf_name = "PortChannel0001.10"
        ip_addr = "192.169.1.1/24"
        vrf = "Vrf1"
        result = self.runner.invoke(config.config.commands['interface'].commands['ip'].commands['add'], [intf_name, ip_addr], obj=ctx_obj)
        assert result.exit_code != 0
        assert self.get_err_str(result.output) == 'Sub port interface name is too long!'

        result = self.runner.invoke(config.config.commands['interface'].commands['vrf'].commands['bind'], [intf_name, vrf], obj=ctx_obj)
        assert result.exit_code != 0
        assert self.get_err_str(result.output) == 'Sub port interface name is too long!'

    @patch('config.main.run_command')
    def test_subport_validate_vlan_id(self, mock_run, basic_suite):
        (config, show, db) = basic_suite
        ctx_obj = {'config_db': db['config_db']}

        intf_name = "Ethernet0.0"
        ip_addr = "192.169.1.1/24"
        result = self.runner.invoke(config.config.commands['interface'].commands['ip'].commands['add'], [intf_name, ip_addr], obj=ctx_obj)
        assert result.exit_code != 0
        assert self.get_err_str(result.output) == 'Invalid VLAN ID {} (1-4094)'.format(intf_name.split('.')[1])

        intf_name = "Ethernet0.4095"
        result = self.runner.invoke(config.config.commands['interface'].commands['ip'].commands['add'], [intf_name, ip_addr], obj=ctx_obj)
        assert result.exit_code != 0
        assert self.get_err_str(result.output) == 'Invalid VLAN ID {} (1-4094)'.format(intf_name.split('.')[1])

        intf_name = "Ethernet0.abc"
        result = self.runner.invoke(config.config.commands['interface'].commands['ip'].commands['add'], [intf_name, ip_addr], obj=ctx_obj)
        assert result.exit_code != 0
        assert self.get_err_str(result.output) == 'Invalid VLAN ID {} (1-4094)'.format(intf_name.split('.')[1])

    @patch('config.main.run_command')
    @pytest.mark.parametrize("oper, test_args, expect_result, err_args", [
        ("add", ["Ethernet0", "192.169.1.1/24"], "pass", ""),
        ("add", ["Ethernet0.10", "192.169.2.1/24"], "fail", ["Ethernet0","L3"]),
        ("remove", ["Ethernet0", "192.169.1.1/24"], "pass", ""),
        ("add", ["Ethernet0.10", "192.169.2.1/24"], "pass", ""),
        ("add", ["Ethernet0", "192.169.1.1/24"], "fail", ["Ethernet0.10","subport"]),
        ("remove", ["Ethernet0.10", "192.169.2.1/24"], "pass", ""),
        ("add", ["Ethernet0", "192.169.1.1/24"], "pass", ""),
        ("remove", ["Ethernet0", "192.169.1.1/24"], "pass", "")
    ])
    def test_subport_can_not_coexist_with_eth_l3intf(self, mock_run, basic_suite, oper, test_args, expect_result, err_args) :
        (config, show, db) = basic_suite
        config_db = db['config_db']
        ctx_obj = {'config_db': config_db}

        result = self.runner.invoke(config.config.commands['interface'].commands['ip'].commands[oper], test_args, obj=ctx_obj)
        print result.output
        if expect_result == "pass":
            assert result.exit_code == 0
            if oper == "add" and '.' in test_args[0]:
                assert True == self.is_subport_exist(config_db, test_args[0])
            else:
                assert False == self.is_subport_exist(config_db, test_args[1])
        else:
            assert result.exit_code != 0
            assert self.get_err_str(result.output) == '{} is a {} interface!'.format(err_args[0], err_args[1])

    @patch('config.main.run_command')
    @pytest.mark.parametrize("oper, test_args, expect_result, err_args", [
        ("add", ["PortChannel1", "192.169.1.1/24"], "pass", ""),
        ("add", ["PortChannel1.10", "192.169.2.1/24"], "fail", ["PortChannel1","L3"]),
        ("remove", ["PortChannel1", "192.169.1.1/24"], "pass", ""),
        ("add", ["PortChannel1.10", "192.169.2.1/24"], "pass", ""),
        ("add", ["PortChannel1", "192.169.1.1/24"], "fail", ["PortChannel1.10","subport"]),
        ("remove", ["PortChannel1.10", "192.169.2.1/24"], "pass", ""),
        ("add", ["PortChannel1", "192.169.1.1/24"], "pass", ""),
        ("remove", ["PortChannel1", "192.169.1.1/24"], "pass", "")
    ])
    def test_subport_can_not_coexist_with_pc_l3intf(self, mock_run, basic_suite, oper, test_args, expect_result, err_args) :
        (config, show, db) = basic_suite
        config_db = db['config_db']
        ctx_obj = {'config_db': config_db}

        result = self.runner.invoke(config.config.commands['interface'].commands['ip'].commands[oper], test_args, obj=ctx_obj)
        if expect_result == "pass":
            assert result.exit_code == 0
            if oper == "add" and '.' in test_args[0]:
                assert True == self.is_subport_exist(config_db, test_args[0])
            else:
                assert False == self.is_subport_exist(config_db, test_args[0])
        else:
            assert result.exit_code != 0
            assert self.get_err_str(result.output) == '{} is a {} interface!'.format(err_args[0], err_args[1])

    @patch('config.main.run_command')
    @pytest.mark.parametrize("oper, test_args, expect_result, err_args", [
        ("add", ["Ethernet0.10", "192.169.1.1/24"], "pass", ""),
        ("add", ["PortChannel1", "Ethernet0"], "fail", ["Ethernet0.10","a subport interface"]),
        ("remove", ["Ethernet0.10", "192.169.1.1/24"], "pass", ""),
        ("add", ["PortChannel1", "Ethernet0"], "pass", ""),
        ("add", ["Ethernet0.10", "192.169.1.1/24"], "fail", ["Ethernet0","portchannel member"]),
        ("del", ["PortChannel1", "Ethernet0"], "pass", "")
    ])
    def test_subport_of_eth_can_not_coexist_with_pc_member(self, mock_run, basic_suite, oper, test_args, expect_result, err_args):
        (config, show, db) = basic_suite
        ctx_obj = {'config_db': db['config_db']}
        pc_ctx_obj = {'db': db['config_db']}

        if 'Ethernet' in test_args[0]:
            result = self.runner.invoke(config.config.commands['interface'].commands['ip'].commands[oper], test_args, obj=ctx_obj)
        else:
            result = self.runner.invoke(config.config.commands['portchannel'].commands['member'].commands[oper], test_args, obj=pc_ctx_obj)

        if expect_result == "pass":
            assert result.exit_code == 0
        else:
            assert result.exit_code != 0
            assert self.get_err_str(result.output) == '{} is {}'.format(err_args[0], err_args[1])

    @patch('config.main.run_command')
    @pytest.mark.parametrize("oper, test_args, expect_result", [
        ("add", ["Ethernet0.10","192.169.1.1/24"], "pass"),
        ("add", ["10"], "fail"),
        ("add", ["20"], "pass"),
        ("add", ["Ethernet0.20","192.169.2.1/24"], "fail"),
        ("add", ["PortChannel1.30","192.169.3.1/24"], "pass"),
        ("add", ["30"], "fail"),
        ("add", ["40"], "pass"),
        ("add", ["PortChannel1.40","192.169.4.1/24"], "fail")
    ])
    def test_subport_vlan_can_not_coexist_with_normal_vlan(self, mock_run, basic_suite, oper, test_args, expect_result) :
        (config, show, db) = basic_suite
        ctx_obj = {'config_db': db['config_db']}
        vlan_ctx_obj = {'db': db['config_db']}

        if len(test_args) == 2:
            result = self.runner.invoke(config.config.commands['interface'].commands['ip'].commands[oper], test_args, obj=ctx_obj)
        else:
            result = self.runner.invoke(config.config.commands['vlan'].commands[oper], test_args, obj=vlan_ctx_obj)

        if expect_result == "pass":
            assert result.exit_code == 0
        else:
            assert result.exit_code != 0
            if len(test_args) == 2:
                assert self.get_err_str(result.output) == 'Vlan{} already exist'.format(test_args[0].split('.')[1])
            else:
                assert self.get_err_str(result.output) == 'Vlan{} already created by subport'.format(test_args[0])

    @classmethod
    def teardown_class(cls):
        # print("TEARDOWN")
        pass

