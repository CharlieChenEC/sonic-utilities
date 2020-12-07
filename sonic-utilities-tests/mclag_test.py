import pytest
import platform
from distutils.version import StrictVersion
from click.testing import CliRunner
from natsort import natsorted

class TestMclag(object):
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
    def mclag_db(self, basic_suite):
        (_, _, db) = basic_suite
        self.config_db_tables.update({
            'mclag_domain'      : 'MCLAG_DOMAIN',
            'mclag_interface'   : 'MCLAG_INTERFACE',
            'mclag_unique_ip'   : 'MCLAG_UNIQUEIP_TABLE'
        })
        self.app_db_tables.update({
            'port'  : 'PORT_TABLE',
            'lag'   : 'LAG_TABLE'
        })
        self.state_db_tables.update({
            'mclag_domain'      : 'MCLAG_TABLE',
            'mclag_local_intf'  : 'MCLAG_LOCAL_INTF_TABLE',
            'mclag_remote_intf' : 'MCLAG_REMOTE_INTF_TABLE'
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

    @pytest.mark.skipif(StrictVersion(platform.linux_distribution()[1]) <= StrictVersion('8.9'), reason="Debian 8.9 or before has no support")
    @pytest.mark.parametrize("test_input", [
        (["1", "192.168.1.100", "192.168.2.100", ""]),
        (["2", "192.168.3.100", "192.168.4.100", "Ethernet100"]),
        (["3", "192.168.5.100", "192.168.6.100", "PortChannel100"]),
    ])
    def test_domain_add_del(self, basic_suite, test_input):
        (config, show, db) = basic_suite
        config_db = db['config_db']
        ctx_obj = {'db': config_db}
        domain_id = test_input[0]
        local_ip_addr = test_input[1]
        peer_ip_addr = test_input[2]
        peer_ifname = test_input[3]
        if peer_ifname == "":
            result = self.runner.invoke(config.config.commands['mclag'].commands['add'], [domain_id, local_ip_addr, peer_ip_addr], obj=ctx_obj)
        else:
            result = self.runner.invoke(config.config.commands['mclag'].commands['add'], [domain_id, local_ip_addr, peer_ip_addr, peer_ifname], obj=ctx_obj)
        assert result.exit_code == 0
        tbl = config_db.get_table(self.config_db_tables['mclag_domain'])
        keys = tbl.keys()
        assert len(keys) == 1
        assert keys[0] == domain_id
        entry = config_db.get_entry(self.config_db_tables['mclag_domain'], domain_id)
        assert entry != {}
        assert entry['source_ip'] == local_ip_addr
        assert entry['peer_ip'] == peer_ip_addr
        if peer_ifname != "":
            assert entry['peer_link'] == peer_ifname

        result = self.runner.invoke(config.config.commands['mclag'].commands['del'], [domain_id], obj=ctx_obj)
        assert result.exit_code == 0
        tbl = config_db.get_table(self.config_db_tables['mclag_domain'])
        assert tbl == {}

    @pytest.mark.skipif(StrictVersion(platform.linux_distribution()[1]) <= StrictVersion('8.9'), reason="Debian 8.9 or before has no support")
    @pytest.mark.parametrize("test_args, missing_arg", [
        ([],                        "domain_id"),
        (["1"],                     "local_ip_addr"),
        (["1", "192.168.1.100"],    "peer_ip_addr"),
    ])
    def test_domain_validate_required_args(self, basic_suite, test_args, missing_arg):
        (config, show, db) = basic_suite
        config_db = db['config_db']
        ctx_obj = {'db': config_db}
        result = self.runner.invoke(config.config.commands['mclag'].commands['add'], test_args, obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Missing argument \'<{}>\'.'.format(missing_arg)

    def test_domain_validate_domain_id(self, basic_suite):
        (config, show, db) = basic_suite
        config_db = db['config_db']
        ctx_obj = {'db': config_db}
        domain_id = 'abc'
        result = self.runner.invoke(config.config.commands['mclag'].commands['add'], [domain_id, '', ''], obj=ctx_obj)
        assert result.exit_code == 1
        assert str(result.exception) == 'invalid literal for int() with base 10: \'{}\''.format(domain_id)

        domain_id = '0'
        result = self.runner.invoke(config.config.commands['mclag'].commands['add'], [domain_id, '', ''], obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Invalid Domain ID {}. Valid range [1 to 4095].'.format(domain_id)

        domain_id = '4096'
        result = self.runner.invoke(config.config.commands['mclag'].commands['add'], [domain_id, '', ''], obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Invalid Domain ID {}. Valid range [1 to 4095].'.format(domain_id)

    @pytest.mark.skipif(StrictVersion(platform.linux_distribution()[1]) <= StrictVersion('8.9'), reason="Debian 8.9 or before has no support")
    @pytest.mark.parametrize("test_input", [
        (["abc"]),
        (["1.2.3.256"]),
    ])
    def test_domain_validate_local_ip_addr(self, basic_suite, test_input):
        (config, show, db) = basic_suite
        config_db = db['config_db']
        ctx_obj = {'db': config_db}
        domain_id = '1'
        local_ip_addr = test_input[0]
        result = self.runner.invoke(config.config.commands['mclag'].commands['add'], [domain_id, local_ip_addr, ''], obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Invalid Local IP address {}.'.format(local_ip_addr)

    @pytest.mark.skipif(StrictVersion(platform.linux_distribution()[1]) <= StrictVersion('8.9'), reason="Debian 8.9 or before has no support")
    @pytest.mark.parametrize("test_input", [
        (["abc"]),
        (["1.2.3.256"]),
    ])
    def test_domain_validate_peer_ip_addr(self, basic_suite, test_input):
        (config, show, db) = basic_suite
        config_db = db['config_db']
        ctx_obj = {'db': config_db}
        domain_id = '1'
        local_ip_addr = '192.168.1.100'
        peer_ip_addr = test_input[0]
        result = self.runner.invoke(config.config.commands['mclag'].commands['add'], [domain_id, local_ip_addr, peer_ip_addr], obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Invalid Peer IP address {}.'.format(peer_ip_addr)

    def test_domain_validate_peer_ifname(self, basic_suite):
        (config, show, db) = basic_suite
        config_db = db['config_db']
        ctx_obj = {'db': config_db}
        domain_id = '1'
        local_ip_addr = '192.168.1.100'
        peer_ip_addr = '192.168.2.100'
        invalid_peer_ifname = 'abc'
        result = self.runner.invoke(config.config.commands['mclag'].commands['add'], [domain_id, local_ip_addr, peer_ip_addr, invalid_peer_ifname], obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Invalid Peer interface name {}. It can only be ethernet port or port channel.'.format(invalid_peer_ifname)

        inexistent_peer_ifname = 'Ethernet200'
        result = self.runner.invoke(config.config.commands['mclag'].commands['add'], [domain_id, local_ip_addr, peer_ip_addr, inexistent_peer_ifname], obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Invalid Peer interface name {}. Please enter existing interface.'.format(inexistent_peer_ifname)

    def test_member_add_del(self, basic_suite):
        (config, show, db) = basic_suite
        config_db = db['config_db']
        ctx_obj = {'db': config_db}
        domain_id = '1'
        local_ip_addr = '192.168.1.100'
        peer_ip_addr = '192.168.2.100'
        result = self.runner.invoke(config.config.commands['mclag'].commands['add'], [domain_id, local_ip_addr, peer_ip_addr], obj=ctx_obj)
        assert result.exit_code == 0

        portchannel_name = 'PortChannel100'
        result = self.runner.invoke(config.config.commands['mclag'].commands['member'].commands['add'], [domain_id, portchannel_name], obj=ctx_obj)
        assert result.exit_code == 0
        tbl = config_db.get_table(self.config_db_tables['mclag_interface'])
        keys = tbl.keys()
        assert len(keys) == 1
        assert keys[0][0] == domain_id
        assert keys[0][1] == portchannel_name

        result = self.runner.invoke(config.config.commands['mclag'].commands['member'].commands['del'], [domain_id, portchannel_name], obj=ctx_obj)
        assert result.exit_code == 0
        tbl = config_db.get_table(self.config_db_tables['mclag_interface'])
        keys = tbl.keys()
        assert len(keys) == 0

    def test_member_validate_required_args(self, basic_suite):
        (config, show, db) = basic_suite
        config_db = db['config_db']
        ctx_obj = {'db': config_db}
        domain_id = '1'
        result = self.runner.invoke(config.config.commands['mclag'].commands['member'].commands['add'], [], obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Missing argument \'<domain_id>\'.'

        result = self.runner.invoke(config.config.commands['mclag'].commands['member'].commands['add'], [domain_id], obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Missing argument \'<portchannel_name>\'.'

    def test_member_validate_domain_id(self, basic_suite):
        (config, show, db) = basic_suite
        config_db = db['config_db']
        ctx_obj = {'db': config_db}
        domain_id = '1'
        portchannel_name = 'PortChannel100'
        result = self.runner.invoke(config.config.commands['mclag'].commands['member'].commands['add'], [domain_id, portchannel_name], obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'MCLAG Domain {} doesn\'t exist.'.format(domain_id)

    def test_member_validate_portchannel_name(self, basic_suite):
        (config, show, db) = basic_suite
        config_db = db['config_db']
        ctx_obj = {'db': config_db}
        domain_id = '1'
        local_ip_addr = '192.168.1.100'
        peer_ip_addr = '192.168.2.100'
        result = self.runner.invoke(config.config.commands['mclag'].commands['add'], [domain_id, local_ip_addr, peer_ip_addr], obj=ctx_obj)
        assert result.exit_code == 0

        ethernet_name = 'Ethernet0'
        result = self.runner.invoke(config.config.commands['mclag'].commands['member'].commands['add'], [domain_id, ethernet_name], obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Invalid portchannel name {}. MCLAG interfaces can be only portchannels.'.format(ethernet_name)

        inexistent_portchannel = 'PortChannel200'
        result = self.runner.invoke(config.config.commands['mclag'].commands['member'].commands['add'], [domain_id, inexistent_portchannel], obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Invalid portchannel name {}. Please enter existing portchannel.'.format(inexistent_portchannel)

    def test_unique_ip_add_del(self, basic_suite):
        (config, show, db) = basic_suite
        config_db = db['config_db']
        ctx_obj = {'db': config_db}
        vlan_interface = 'Vlan100'
        result = self.runner.invoke(config.config.commands['mclag'].commands['unique-ip'].commands['add'], [vlan_interface], obj=ctx_obj)
        assert result.exit_code == 0
        tbl = config_db.get_table(self.config_db_tables['mclag_unique_ip'])
        keys = tbl.keys()
        assert len(keys) == 1
        assert keys[0] == vlan_interface

        result = self.runner.invoke(config.config.commands['mclag'].commands['unique-ip'].commands['del'], [vlan_interface], obj=ctx_obj)
        assert result.exit_code == 0
        tbl = config_db.get_table(self.config_db_tables['mclag_unique_ip'])
        keys = tbl.keys()
        assert len(keys) == 0

    def test_unique_ip_validate_required_args(self, basic_suite):
        (config, show, db) = basic_suite
        config_db = db['config_db']
        ctx_obj = {'db': config_db}
        domain_id = '1'
        result = self.runner.invoke(config.config.commands['mclag'].commands['unique-ip'].commands['add'], [], obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Missing argument \'<vlan_interface>\'.'

    def test_unique_ip_validate_vlan_interface(self, basic_suite):
        (config, show, db) = basic_suite
        config_db = db['config_db']
        ctx_obj = {'db': config_db}

        ethernet_name = 'Ethernet0'
        result = self.runner.invoke(config.config.commands['mclag'].commands['unique-ip'].commands['add'], [ethernet_name], obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Invalid Vlan interface {}. Only VLAN interface supported currently.'.format(ethernet_name)

        inexistent_vlan = 'Vlan999'
        result = self.runner.invoke(config.config.commands['mclag'].commands['unique-ip'].commands['add'], [inexistent_vlan], obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Invalid Vlan interface {}. Please enter existing Vlan.'.format(inexistent_vlan)

    class mclagBriefOutput:
        def __init__(self, domain_id='', role='', session_status='', peer_link_status='', source_addr='', peer_addr='', peer_link='', system_mac='', member_cnt=0, members=[]):
            self.domain_id = domain_id
            self.role = role
            self.session_status = session_status
            self.peer_link_status = peer_link_status
            self.source_addr = source_addr
            self.peer_addr = peer_addr
            self.peer_link = peer_link
            self.system_mac = system_mac
            self.member_cnt = member_cnt
            self.members = members

        def content(self):
            content = ''
            content += '\tDomain ID                    : {}\n'.format(self.domain_id)
            content += '\tRole                         : {}\n'.format(self.role)
            content += '\tSession Status               : {}\n'.format(self.session_status)
            content += '\tPeer Link Status             : {}\n'.format(self.peer_link_status)
            content += '\tSource Address               : {}\n'.format(self.source_addr)
            content += '\tPeer Address                 : {}\n'.format(self.peer_addr)
            content += '\tPeer Link                    : {}\n'.format(self.peer_link)
            content += '\tSystem MAC                   : {}\n'.format(self.system_mac)
            content += '\tNumber of MCLAG Interfaces   : {}\n'.format(self.member_cnt)
            if 0 < self.member_cnt:
                content += '\tMCLAG Interface              Local/Remote Status\n'
                for member in natsorted(self.members):
                    content += '\t{0: <28} {l}/{r}\n'.format(member['name'], l=member['local_status'], r=member['remote_status'])
            content += '\n'
            return content

    def test_show_mclag_brief_no_member(self, basic_suite):
        (config, show, db) = basic_suite
        config_db = db['config_db']
        app_db = db['app_db']
        state_db = db['state_db']
        config_ctx_obj = {'db': config_db}

        # add mclag domain
        domain_id = '2'
        local_ip_addr = '192.168.1.1'
        remote_ip_addr = '192.168.2.1'
        result = self.runner.invoke(config.config.commands['mclag'].commands['add'], [domain_id, local_ip_addr, remote_ip_addr], obj=config_ctx_obj)
        assert result.exit_code == 0

        show_ctx_obj = {'config_db': config_db, 'app_db': app_db, 'state_db': state_db}
        result = self.runner.invoke(show.cli.commands['mclag'].commands['brief'], [], obj=show_ctx_obj)
        output_obj = self.mclagBriefOutput(domain_id=domain_id, source_addr=local_ip_addr, peer_addr=remote_ip_addr)
        assert result.output == output_obj.content()

    def test_show_mclag_brief_one_member(self, basic_suite):
        (config, show, db) = basic_suite
        config_db = db['config_db']
        app_db = db['app_db']
        state_db = db['state_db']
        config_ctx_obj = {'db': config_db}

        # add mclag domain
        domain_id = '2'
        local_ip_addr = '192.168.1.100'
        remote_ip_addr = '192.168.1.200'
        peer_ifname = 'Ethernet100'
        result = self.runner.invoke(config.config.commands['mclag'].commands['add'], [domain_id, local_ip_addr, remote_ip_addr, peer_ifname], obj=config_ctx_obj)
        assert result.exit_code == 0

        # add member to mclag domain
        member = 'PortChannel100'
        result = self.runner.invoke(config.config.commands['mclag'].commands['member'].commands['add'], [domain_id, member], obj=config_ctx_obj)
        assert result.exit_code == 0

        # show mclag brief without state db entry
        show_ctx_obj = {'config_db': config_db, 'app_db': app_db, 'state_db': state_db}
        result = self.runner.invoke(show.cli.commands['mclag'].commands['brief'], [], obj=show_ctx_obj)
        members_obj = [{'name': member, 'local_status': 'Down', 'remote_status': 'Down'}]
        output_obj = self.mclagBriefOutput(domain_id=domain_id, source_addr=local_ip_addr, peer_addr=remote_ip_addr, peer_link=peer_ifname,
                                            member_cnt=1, members=members_obj)
        assert result.output == output_obj.content()

        # prepare entry on app db
        peer_link_status = 'up'
        peer_tbl = self.app_db_tables['port'] if peer_ifname.startswith('Ethernet') else self.app_db_tables['lag']
        app_db.set_entry(peer_tbl, peer_ifname, {'oper_status': peer_link_status})
        local_status = 'up'
        app_db.set_entry(self.app_db_tables['lag'], member, {'oper_status': local_status})

        # prepare entry on state db
        session_status = 'down'
        role = 'active'
        system_mac = 'b8:6a:97:73:6c:96'
        state_db.set_entry(self.state_db_tables['mclag_domain'], domain_id, {'role': role, 'system_mac': system_mac})
        remote_status = 'up'
        state_db.set_entry(self.state_db_tables['mclag_remote_intf'], (domain_id, member), {'oper_status': remote_status})

        # show mclag brief with state db entry
        result = self.runner.invoke(show.cli.commands['mclag'].commands['brief'], [], obj=show_ctx_obj)
        members_obj = [{'name': member, 'local_status': local_status.capitalize(), 'remote_status': remote_status.capitalize()}]
        output_obj = self.mclagBriefOutput(domain_id=domain_id, role=role.capitalize(), session_status=session_status.capitalize(),
                                            peer_link_status=peer_link_status.capitalize(), source_addr=local_ip_addr, peer_addr=remote_ip_addr,
                                            peer_link=peer_ifname, system_mac=system_mac, member_cnt=1, members=members_obj)
        assert result.output == output_obj.content()

    def test_show_mclag_brief_multi_member(self, basic_suite):
        (config, show, db) = basic_suite
        config_db = db['config_db']
        app_db = db['app_db']
        state_db = db['state_db']
        config_ctx_obj = {'db': config_db}

        domain_id = '2'
        local_ip_addr = '192.168.1.100'
        remote_ip_addr = '192.168.1.200'
        peer_ifname = 'Ethernet100'
        result = self.runner.invoke(config.config.commands['mclag'].commands['add'], [domain_id, local_ip_addr, remote_ip_addr, peer_ifname], obj=config_ctx_obj)
        assert result.exit_code == 0

        peer_link_status = 'up'
        peer_tbl = self.app_db_tables['port'] if peer_ifname.startswith('Ethernet') else self.app_db_tables['lag']
        app_db.set_entry(peer_tbl, peer_ifname, {'oper_status': peer_link_status})

        session_status = 'up'
        role = 'active'
        system_mac = 'b8:6a:97:73:6c:96'
        state_db.set_entry(self.state_db_tables['mclag_domain'], domain_id, {'oper_status': session_status, 'role': role, 'system_mac': system_mac})

        members = ['PortChannel100', 'PortChannel101']
        members_obj = []
        remote_status = 'up'
        local_status = 'up'
        for member in members:
            result = self.runner.invoke(config.config.commands['mclag'].commands['member'].commands['add'], [domain_id, member], obj=config_ctx_obj)
            assert result.exit_code == 0
            app_db.set_entry(self.app_db_tables['lag'], member, {'oper_status': local_status})
            state_db.set_entry(self.state_db_tables['mclag_remote_intf'], (domain_id, member), {'oper_status': remote_status})
            members_obj.append({'name': member, 'local_status': local_status.capitalize(), 'remote_status': remote_status.capitalize()})

        show_ctx_obj = {'config_db': config_db, 'app_db': app_db, 'state_db': state_db}
        result = self.runner.invoke(show.cli.commands['mclag'].commands['brief'], [], obj=show_ctx_obj)
        output_obj = self.mclagBriefOutput(domain_id=domain_id, role=role.capitalize(), session_status=session_status.capitalize(),
                                            peer_link_status=peer_link_status.capitalize(), source_addr=local_ip_addr, peer_addr=remote_ip_addr,
                                            peer_link=peer_ifname, system_mac=system_mac, member_cnt=len(members_obj), members=members_obj)
        assert result.output == output_obj.content()

    def test_show_mclag_brief_no_domain(self, basic_suite):
        (config, show, db) = basic_suite
        config_db = db['config_db']
        app_db = db['app_db']
        state_db = db['state_db']
        show_ctx_obj = {'config_db': config_db, 'app_db': app_db, 'state_db': state_db}
        result = self.runner.invoke(show.cli.commands['mclag'].commands['brief'], [], obj=show_ctx_obj)
        assert result.output.strip('\n') == 'No MCLAG domain configured.'

    class mclagInterfaceOutput:
        def __init__(self, local_status='Down', remote_status='Down', isolate_status='No'):
            self.local_status = local_status
            self.remote_status = remote_status
            self.isolate_status = isolate_status

        def content(self):
            content = ''
            content += '\tLocal/Remote Status          : {l}/{r}\n'.format(l=self.local_status, r=self.remote_status)
            content += '\tIsolateWithPeerLink          : {}\n'.format(self.isolate_status)
            content += '\n'
            return content

    def test_show_mclag_interface(self, basic_suite):
        (config, show, db) = basic_suite
        config_db = db['config_db']
        app_db = db['app_db']
        state_db = db['state_db']
        config_ctx_obj = {'db': config_db}

        domain_id = '1'
        local_ip_addr = '192.168.1.100'
        remote_ip_addr = '192.168.1.200'
        result = self.runner.invoke(config.config.commands['mclag'].commands['add'], [domain_id, local_ip_addr, remote_ip_addr], obj=config_ctx_obj)
        assert result.exit_code == 0

        member = 'PortChannel100'
        result = self.runner.invoke(config.config.commands['mclag'].commands['member'].commands['add'], [domain_id, member], obj=config_ctx_obj)
        assert result.exit_code == 0

        # show mclag interface without state db entry
        show_ctx_obj = {'config_db': config_db, 'app_db': app_db, 'state_db': state_db}
        result = self.runner.invoke(show.cli.commands['mclag'].commands['interface'], [domain_id, member], obj=show_ctx_obj)
        output_obj = self.mclagInterfaceOutput()
        assert result.output == output_obj.content()

        # prepare entry on state db
        local_status = 'up'
        app_db.set_entry(self.app_db_tables['lag'], member, {'oper_status': local_status})

        # prepare entry on state db
        remote_status = 'up'
        state_db.set_entry(self.state_db_tables['mclag_remote_intf'], (domain_id, member), {'oper_status': remote_status})
        port_isolate_peer_link = 'true'
        state_db.set_entry(self.state_db_tables['mclag_local_intf'], member, {'port_isolate_peer_link': port_isolate_peer_link})

        # show mclag interface with state db entry
        result = self.runner.invoke(show.cli.commands['mclag'].commands['interface'], [domain_id, member], obj=show_ctx_obj)
        isolate_status = 'Yes' if port_isolate_peer_link == 'true' else 'No'
        output_obj = self.mclagInterfaceOutput(local_status=local_status.capitalize(), remote_status=remote_status.capitalize(), isolate_status=isolate_status)
        assert result.output == output_obj.content()

    @pytest.mark.skipif(StrictVersion(platform.linux_distribution()[1]) <= StrictVersion('8.9'), reason="Debian 8.9 or before has no support")
    @pytest.mark.parametrize("test_args, missing_arg", [
        ([],	"domain_id"),
        (["1"],	"portchannel_name"),
    ])
    def test_show_mclag_interface_validate_required_args(self, basic_suite, test_args, missing_arg):
        (config, show, db) = basic_suite
        config_db = db['config_db']
        app_db = db['app_db']
        state_db = db['state_db']
        show_ctx_obj = {'config_db': config_db, 'app_db': app_db, 'state_db': state_db}

        result = self.runner.invoke(show.cli.commands['mclag'].commands['interface'], test_args, obj=show_ctx_obj)
        assert self.get_err_str(result.output) == 'Missing argument \'<{}>\'.'.format(missing_arg)

    def test_show_mclag_interface_validate_domain_id(self, basic_suite):
        (config, show, db) = basic_suite
        config_db = db['config_db']
        app_db = db['app_db']
        state_db = db['state_db']
        show_ctx_obj = {'config_db': config_db, 'app_db': app_db, 'state_db': state_db}

        inexistent_domain = '1'
        result = self.runner.invoke(show.cli.commands['mclag'].commands['interface'], [inexistent_domain, 'PortChannel1000'], obj=show_ctx_obj)
        assert result.output.strip('\n') == 'Domain {} is not configured.'.format(inexistent_domain)

        invalid_domain_id = 'abc'
        result = self.runner.invoke(show.cli.commands['mclag'].commands['interface'], [invalid_domain_id, 'PortChannel1000'], obj=show_ctx_obj)
        assert self.get_err_str(result.output) == 'Invalid value for \'<domain_id>\': {} is not a valid integer'.format(invalid_domain_id)

    def test_show_mclag_interface_validate_portchannel_name(self, basic_suite):
        (config, show, db) = basic_suite
        config_db = db['config_db']
        app_db = db['app_db']
        state_db = db['state_db']
        config_ctx_obj = {'db': config_db}

        domain_id = '1'
        local_ip_addr = '192.168.1.100'
        remote_ip_addr = '192.168.1.200'
        result = self.runner.invoke(config.config.commands['mclag'].commands['add'], [domain_id, local_ip_addr, remote_ip_addr], obj=config_ctx_obj)
        assert result.exit_code == 0

        show_ctx_obj = {'config_db': config_db, 'app_db': app_db, 'state_db': state_db}
        invalid_portchannel = 'Ethernet100'
        result = self.runner.invoke(show.cli.commands['mclag'].commands['interface'], [domain_id, invalid_portchannel], obj=show_ctx_obj)
        assert self.get_err_str(result.output) == 'Invalid portchannel name {}.'.format(invalid_portchannel)

        not_configured_portchannel = 'PortChannel100'
        result = self.runner.invoke(show.cli.commands['mclag'].commands['interface'], [domain_id, not_configured_portchannel], obj=show_ctx_obj)
        assert result.output.strip('\n') == 'Domain {} member {} is not configured.'.format(domain_id, not_configured_portchannel)

    def test_show_mclag_unique_ip(self, basic_suite):
        (config, show, db) = basic_suite
        config_db = db['config_db']
        app_db = db['app_db']
        state_db = db['state_db']
        show_ctx_obj = {'config_db': config_db, 'app_db': app_db, 'state_db': state_db}
        result = self.runner.invoke(show.cli.commands['mclag'].commands['unique-ip'], [], obj=show_ctx_obj)
        assert result.output.strip('\n') == '\tUnique IP                    :'

        config_ctx_obj = {'db': config_db}
        vlan100_interface = 'Vlan100'
        result = self.runner.invoke(config.config.commands['mclag'].commands['unique-ip'].commands['add'], [vlan100_interface], obj=config_ctx_obj)
        assert result.exit_code == 0

        result = self.runner.invoke(show.cli.commands['mclag'].commands['unique-ip'], [], obj=show_ctx_obj)
        assert result.output.strip('\n') == '\tUnique IP                    : {}'.format(vlan100_interface)

        vlan101_interface = 'Vlan101'
        result = self.runner.invoke(config.config.commands['mclag'].commands['unique-ip'].commands['add'], [vlan101_interface], obj=config_ctx_obj)
        assert result.exit_code == 0

        result = self.runner.invoke(show.cli.commands['mclag'].commands['unique-ip'], [], obj=show_ctx_obj)
        assert result.output.strip('\n') == '\tUnique IP                    : {}, {}'.format(vlan100_interface, vlan101_interface)

    @classmethod
    def teardown_class(cls):
        # print("TEARDOWN")
        pass
