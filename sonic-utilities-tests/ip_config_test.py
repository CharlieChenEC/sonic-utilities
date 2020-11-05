import pytest
import platform
from distutils.version import StrictVersion
from click.testing import CliRunner
from natsort import natsorted
from mock import patch

class TestIpconfig(object):
    @classmethod
    def setup_class(cls):
        # print("SETUP")
        cls.runner = CliRunner()
        cls.config_db_tables = {}
        cls.app_db_tables = {}
        cls.state_db_tables = {}

    @pytest.fixture(scope='class', autouse=True)
    def basic_suite(self, get_cmd_module):
        (config, show, db) = get_cmd_module
        yield (config, show, db)

    @pytest.fixture(autouse=True)
    def interface_db(self, basic_suite):
        (_, _, db) = basic_suite
        self.config_db_tables.update({
            'interface'      : 'INTERFACE'
        })
        self.app_db_tables.update({
            'interface'  : 'INTF_TABLE'
        })
        self.state_db_tables.update({
            'interface'      : 'INTERFACE_TABLE'
        })
        yield
        for _, table_name in self.config_db_tables.items():
            db['config_db'].delete_table(table_name)
        for _, table_name in self.app_db_tables.items():
            db['app_db'].delete_table(table_name)
        for _, table_name in self.state_db_tables.items():
            db['state_db'].delete_table(table_name)

    def get_err_str(self, result_output):
        return result_output.split('Error: ')[1].strip('\n')

    @patch('config.main.run_command')
    @pytest.mark.skipif(StrictVersion(platform.linux_distribution()[1]) <= StrictVersion('8.9'), reason="Debian 8.9 or before has no support")
    @pytest.mark.parametrize("test_input", [
        (["Ethernet0", "192.169.1.1/24"])
    ])
    def test_ipv4_simple(self, mock_run, basic_suite, test_input):

        (config, show, db) = basic_suite
        config_db = db['config_db']

        ctx_obj = {'config_db': config_db}
        intf_name = test_input[0]
        ip_addr = test_input[1]

        """Add an IP address towards the interface"""
        result = self.runner.invoke(config.config.commands['interface'].commands['ip'].commands['add'], [intf_name, ip_addr], obj=ctx_obj)
        #print result.output
        assert result.exit_code == 0
        tbl = config_db.get_table(self.config_db_tables['interface'])
        keys = tbl.keys()
        assert len(keys) == 2

        """Remove an IP address from the interface"""
        tbl = config_db.get_table(self.config_db_tables['interface'])
        #mock_run.return_value = True # mock run_cmmand

        result = self.runner.invoke(config.config.commands['interface'].commands['ip'].commands['remove'], [intf_name, ip_addr], obj=ctx_obj)
        #print result.output
        assert result.exit_code == 0
        tbl = config_db.get_table(self.config_db_tables['interface'])
        keys = tbl.keys()
        assert len(keys) == 0

    @patch('config.main.run_command')
    def test_ipv4_primary_secondary(self, mock_run, basic_suite)                                                                                                                                     :
        (config, show, db) = basic_suite
        config_db = db['config_db']
        ctx_obj = {'config_db': config_db}

        test_sequence = [
        (["add", "Ethernet0", "192.169.2.1/24", "secondary", "fail"]),      # Error: Primary IPv4 address is not configured for interface: Ethernet0"
        (["add", "Ethernet0", "192.169.1.1/24", "", "pass"]),
        (["add", "Ethernet0", "192.169.2.1/24", "secondary", "pass"]),
        (["add", "Ethernet0", "192.169.3.1/24", "secondary", "pass"]),
        (["add", "Ethernet0", "192.169.1.1/24", "", "fail"]),               # (add twice) Error: IP address 192.169.1.1/24 overlaps with existing subnet
        (["add", "Ethernet0", "192.169.4.1/24", ""  , "fail"]),             # Error: Primary address already exists
        (["add", "Ethernet0", "192.169.2.1/24", "secondary", "fail"]),      # (add twice) Error: IP address 192.169.2.1/24 overlaps with existing subnet
        (["add", "Ethernet0", "192.169.1.1/24", "secondary", "fail"]),      # Error: IP address 192.169.1.1/24 overlaps with existing subnet
        (["add", "Ethernet0", "192.169.2.1/24", "", "fail"]),               # Error: IP address 192.169.2.1/24 overlaps with existing subnet
        (["remove", "Ethernet0", "192.169.1.1/24", "secondary", "fail"]),   # Error: No such address (192.169.1.1/24) configured on this interface as secondary address
        (["remove", "Ethernet0", "192.169.2.1/24", "", "fail"]),            # Error: No such address (192.169.2.1/24) configured on this interface as primary address
        (["remove", "Ethernet0", "192.169.1.1/24", "", "fail"]),            # Error: Primary IPv4 address delete not permitted when secondary IPv4 address exists
        (["remove", "Ethernet0", "192.169.4.1/24", "secondary", "fail"]),   # Error: No such address (192.169.4.1/24) configured on this interface
        (["remove", "Ethernet0", "192.169.2.1/24", "secondary", "pass"]),
        (["remove", "Ethernet0", "192.169.3.1/24", "secondary", "pass"]),
        (["remove", "Ethernet0", "192.169.1.1/24", "", "pass"]),
        ]

        for data in test_sequence:
            do_action = data[0]
            intf_name = data[1]
            ip_addr = data[2]
            secondary = data[3]
            expect_result = data[4]

            """Add an IP address towards the interface"""
            if do_action == "add":
                if secondary != "":
                    result = self.runner.invoke(config.config.commands['interface'].commands['ip'].commands['add'], [intf_name, ip_addr, "--secondary"], obj=ctx_obj)
                else:
                    result = self.runner.invoke(config.config.commands['interface'].commands['ip'].commands['add'], [intf_name, ip_addr], obj=ctx_obj)
            else:
                #config.run_command.return_value = True # mock run_cmmand
                if secondary != "":
                    result = self.runner.invoke(config.config.commands['interface'].commands['ip'].commands['remove'], [intf_name, ip_addr, "--secondary"], obj=ctx_obj)
                else:
                    result = self.runner.invoke(config.config.commands['interface'].commands['ip'].commands['remove'], [intf_name, ip_addr], obj=ctx_obj)

            #print result.output
            if expect_result == "pass":
                assert result.exit_code == 0
            else:
                assert result.exit_code != 0

        tbl = config_db.get_table(self.config_db_tables['interface'])
        keys = tbl.keys()
        assert len(keys) == 0

    @patch('config.main.run_command')
    def test_ipv4_with_ipv6(self, mock_run, basic_suite)                                                                                                                                     :
        (config, show, db) = basic_suite
        config_db = db['config_db']
        ctx_obj = {'config_db': config_db}

        test_sequence = [
        (["add", "Ethernet0", "192.169.1.1/24", "", "pass"]),
        (["add", "Ethernet0", "192.169.2.1/24", "--secondary", "pass"]),
        (["add", "Ethernet0", "3fff::1/64", "", "pass"]),
        (["remove", "Ethernet0", "3fff::1/64", "", "pass"]),
        (["remove", "Ethernet0", "192.169.2.1/24", "--secondary", "pass"]),
        (["remove", "Ethernet0", "192.169.1.1/24", "", "pass"]),
        ]

        for data in test_sequence:
            do_action = data[0]
            intf_name = data[1]
            ip_addr = data[2]
            secondary = data[3]
            expect_result = data[4]

            """Add an IP address towards the interface"""
            if do_action == "add":
                if secondary != "":
                    result = self.runner.invoke(config.config.commands['interface'].commands['ip'].commands['add'], [intf_name, ip_addr, "--secondary"], obj=ctx_obj)
                else:
                    result = self.runner.invoke(config.config.commands['interface'].commands['ip'].commands['add'], [intf_name, ip_addr], obj=ctx_obj)
            else:
                if secondary != "":
                    result = self.runner.invoke(config.config.commands['interface'].commands['ip'].commands['remove'], [intf_name, ip_addr, "--secondary"], obj=ctx_obj)
                else:
                    result = self.runner.invoke(config.config.commands['interface'].commands['ip'].commands['remove'], [intf_name, ip_addr], obj=ctx_obj)

            #print result.output
            if expect_result == "pass":
                assert result.exit_code == 0
            else:
                assert result.exit_code != 0

        tbl = config_db.get_table(self.config_db_tables['interface'])
        keys = tbl.keys()
        assert len(keys) == 0

    @classmethod
    def teardown_class(cls):
        # print("TEARDOWN")
        pass
