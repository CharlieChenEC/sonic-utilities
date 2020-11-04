import re
import pytest
import platform
from distutils.version import StrictVersion
from click.testing import CliRunner
from natsort import natsorted

class TestPVlan(object):
    @classmethod
    def setup_class(cls):
        # print("SETUP")
        cls.runner = CliRunner()

    @pytest.fixture(scope='class', autouse=True)
    def basic_suite(self, get_cmd_module):
        (config, show, db) = get_cmd_module
        yield (config, show, db)

    def is_table_key_exist(self, db, table, key):
        tbl = db.get_table(table)
        fvs = tbl.get(key)
        return True if fvs != None else False

    def is_table_entry_exists(self, db, table, keyregex, attributes):
        tbl = db.get_table(table)
        keys = tbl.keys()

        extra_info = []
        for key in keys:
            if re.match(keyregex, key) is None:
                continue

            fvs = tbl.get(key)
            assert fvs, "Error reading from table %s" % table

            d_attributes = dict(attributes)
            for k, v in fvs.items():
                if k in d_attributes and d_attributes[k] == v:
                    del d_attributes[k]

            if len(d_attributes) != 0:
                extra_info.append("Desired attributes %s was not found for key %s" % (str(d_attributes), key))
            else:
                return True, extra_info
        else:
            if not extra_info:
                extra_info.append("Desired key regex %s was not found" % str(keyregex))
            return False, extra_info

    def is_cfgdb_vlan_exist(self, db, vlan_id):
        return self.is_table_key_exist(db['config_db'], "VLAN", "Vlan"+vlan_id)

    def is_cfgdb_pvlan_association_exist(self, db, primary_vid, secondary_vid):
        return self.is_table_key_exist(db['config_db'], "PVLAN_ASSOCIATION", ("Vlan"+primary_vid, "Vlan"+secondary_vid))

    def check_cfgdb_vlan_fields(self, db, vlan_id, fields):
        return self.is_table_entry_exists(db['config_db'], "VLAN", "Vlan"+vlan_id, fields)

    def get_err_str(self, result_output):
        return result_output.split('Error: ')[1].strip('\n')

    @pytest.mark.skipif(StrictVersion(platform.linux_distribution()[1]) <= StrictVersion('8.9'), reason="Debian 8.9 or before has no support")
    @pytest.mark.parametrize("vlan_type", [
        (None),
        ("primary"),
        ("community"),
        ("isolated"),
    ])
    def test_pvlan_add_del(self, basic_suite, vlan_type):
        (config, show, db) = basic_suite
        ctx_obj = {'db': db['config_db']}
        vlan_id = '200'
        args = [vlan_id]
        if vlan_type:
            args.append(vlan_type)
        result = self.runner.invoke(config.config.commands['vlan'].commands['add'], args, obj=ctx_obj)
        assert result.exit_code == 0

        # check config database
        assert True == self.is_cfgdb_vlan_exist(db, vlan_id)

        expect_fields = [("vlanid", vlan_id)]
        if vlan_type:
            expect_fields.append(("private_type", vlan_type))
        (found, extra) = self.check_cfgdb_vlan_fields(db, vlan_id, expect_fields)
        assert found, str(extra)

        result = self.runner.invoke(config.config.commands['vlan'].commands['del'], [vlan_id], obj=ctx_obj)
        assert result.exit_code == 0
        assert False == self.is_cfgdb_vlan_exist(db, vlan_id)

    def test_pvlan_add_validate_required_args(self, basic_suite):
        (config, show, db) = basic_suite
        ctx_obj = {'db': db['config_db']}
        result = self.runner.invoke(config.config.commands['vlan'].commands['add'], [], obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Missing argument \'<vid>\'.'

    def test_pvlan_add_validate_vlan_id(self, basic_suite):
        (config, show, db) = basic_suite
        ctx_obj = {'db': db['config_db']}
        vlan_id = 'abc'
        result = self.runner.invoke(config.config.commands['vlan'].commands['add'], [vlan_id], obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Invalid value for \'<vid>\': {} is not a valid integer'.format(vlan_id)

        vlan_id = '0'
        result = self.runner.invoke(config.config.commands['vlan'].commands['add'], [vlan_id], obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Invalid VLAN ID {} (1-4094)'.format(vlan_id)

        vlan_id = '4095'
        result = self.runner.invoke(config.config.commands['vlan'].commands['add'], [vlan_id], obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Invalid VLAN ID {} (1-4094)'.format(vlan_id)

    def test_pvlan_add_with_validate_private_type(self, basic_suite):
        (config, show, db) = basic_suite
        ctx_obj = {'db': db['config_db']}
        vlan_id = '200'
        vlan_type = 'wrong_type'
        result = self.runner.invoke(config.config.commands['vlan'].commands['add'], [vlan_id, vlan_type], obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Invalid value for \'<pvlan_type>\': invalid choice: {}. (choose from primary, community, isolated)'.format(vlan_type)
        assert False == self.is_cfgdb_vlan_exist(db, vlan_id)

    @pytest.mark.skipif(StrictVersion(platform.linux_distribution()[1]) <= StrictVersion('8.9'), reason="Debian 8.9 or before has no support")
    @pytest.mark.parametrize("primary_vid, primary_type, secondary_vid, secondary_type", [
        ("200", "primary", "201", "isolated"),
        ("200", "primary", "201", "community"),
    ])
    def test_pvlan_association_add_del(self, basic_suite, primary_vid, primary_type, secondary_vid, secondary_type):
        (config, show, db) = basic_suite
        ctx_obj = {'db': db['config_db']}
        self.runner.invoke(config.config.commands['vlan'].commands['add'], [primary_vid, primary_type], obj=ctx_obj)
        assert True == self.is_cfgdb_vlan_exist(db, primary_vid)
        self.runner.invoke(config.config.commands['vlan'].commands['add'], [secondary_vid, secondary_type], obj=ctx_obj)
        assert True == self.is_cfgdb_vlan_exist(db, secondary_vid)

        result = self.runner.invoke(config.config.commands['pvlan'].commands['association'].commands['add'], [primary_vid, secondary_vid], obj=ctx_obj)
        assert result.exit_code == 0

        # check config database
        assert True == self.is_cfgdb_pvlan_association_exist(db, primary_vid, secondary_vid)

        result = self.runner.invoke(config.config.commands['pvlan'].commands['association'].commands['del'], [primary_vid, secondary_vid], obj=ctx_obj)
        assert result.exit_code == 0
        assert False == self.is_cfgdb_pvlan_association_exist(db, primary_vid, secondary_vid)

        self.runner.invoke(config.config.commands['vlan'].commands['del'], [primary_vid], obj=ctx_obj)
        assert False == self.is_cfgdb_vlan_exist(db, primary_vid)
        self.runner.invoke(config.config.commands['vlan'].commands['del'], [secondary_vid], obj=ctx_obj)
        assert False == self.is_cfgdb_vlan_exist(db, secondary_vid)

    @pytest.mark.skipif(StrictVersion(platform.linux_distribution()[1]) <= StrictVersion('8.9'), reason="Debian 8.9 or before has no support")
    @pytest.mark.parametrize("test_args, missing_arg", [
        ([],        "primary_vid"),
        (["200"],   "secondary_vid"),
    ])
    def test_pvlan_association_add_validate_required_args(self, basic_suite, test_args, missing_arg):
        (config, show, db) = basic_suite
        ctx_obj = {'db': db['config_db']}
        result = self.runner.invoke(config.config.commands['pvlan'].commands['association'].commands['add'], test_args, obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Missing argument \'<{}>\'.'.format(missing_arg)

    @pytest.mark.skipif(StrictVersion(platform.linux_distribution()[1]) <= StrictVersion('8.9'), reason="Debian 8.9 or before has no support")
    @pytest.mark.parametrize("test_args, invalid_arg", [
        (["abc", "201"],    "primary_vid"),
        (["200", "abc"],    "secondary_vid"),
    ])
    def test_pvlan_association_add_validate_vlan_id_type(self, basic_suite, test_args, invalid_arg):
        (config, show, db) = basic_suite
        ctx_obj = {'db': db['config_db']}
        result = self.runner.invoke(config.config.commands['pvlan'].commands['association'].commands['add'], test_args, obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Invalid value for \'<{}>\': abc is not a valid integer'.format(invalid_arg)

    @pytest.mark.skipif(StrictVersion(platform.linux_distribution()[1]) <= StrictVersion('8.9'), reason="Debian 8.9 or before has no support")
    @pytest.mark.parametrize("test_args, invalid_arg, invalid_vid", [
        (["0",      "0"],    "Primary",     "0"),
        (["4095",   "0"],    "Primary",     "4095"),
        (["200",    "0"],    "Secondary",   "0"),
        (["200", "4095"],    "Secondary",   "4095"),
   ])
    def test_pvlan_association_add_validate_vlan_id_range(self, basic_suite, test_args, invalid_arg, invalid_vid):
        (config, show, db) = basic_suite
        ctx_obj = {'db': db['config_db']}
        result = self.runner.invoke(config.config.commands['pvlan'].commands['association'].commands['add'], test_args, obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Invalid {} VLAN ID {} (1-4094)'.format(invalid_arg, invalid_vid)

    def test_pvlan_association_add_with_nonexist_vlan(self, basic_suite):
        (config, show, db) = basic_suite
        ctx_obj = {'db': db['config_db']}
        primary_vid = "200"
        secondary_vid = "201"
        assert False == self.is_cfgdb_vlan_exist(db, primary_vid)
        assert False == self.is_cfgdb_vlan_exist(db, secondary_vid)

        # primary vlan does not exist
        result = self.runner.invoke(config.config.commands['pvlan'].commands['association'].commands['add'], [primary_vid, secondary_vid], obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Vlan{} doesn\'t exist'.format(primary_vid)

        self.runner.invoke(config.config.commands['vlan'].commands['add'], [primary_vid], obj=ctx_obj)
        assert True == self.is_cfgdb_vlan_exist(db, primary_vid)

        # secondary vlan does not exist
        result = self.runner.invoke(config.config.commands['pvlan'].commands['association'].commands['add'], [primary_vid, secondary_vid], obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Vlan{} doesn\'t exist'.format(secondary_vid)

        assert False == self.is_cfgdb_pvlan_association_exist(db, primary_vid, secondary_vid)
        self.runner.invoke(config.config.commands['vlan'].commands['del'], [primary_vid], obj=ctx_obj)
        assert False == self.is_cfgdb_vlan_exist(db, primary_vid)

    @pytest.mark.skipif(StrictVersion(platform.linux_distribution()[1]) <= StrictVersion('8.9'), reason="Debian 8.9 or before has no support")
    @pytest.mark.parametrize("test_args, invalid_arg", [
        (["abc", "201"],    "primary_vid"),
        (["200", "abc"],    "secondary_vid"),
    ])
    def test_pvlan_association_del_validate_vlan_id_type(self, basic_suite, test_args, invalid_arg):
        (config, show, db) = basic_suite
        ctx_obj = {'db': db['config_db']}
        result = self.runner.invoke(config.config.commands['pvlan'].commands['association'].commands['del'], test_args, obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Invalid value for \'<{}>\': abc is not a valid integer'.format(invalid_arg)

    @pytest.mark.skipif(StrictVersion(platform.linux_distribution()[1]) <= StrictVersion('8.9'), reason="Debian 8.9 or before has no support")
    @pytest.mark.parametrize("test_args, invalid_arg, invalid_vid", [
        (["0",      "0"],    "Primary",     "0"),
        (["4095",   "0"],    "Primary",     "4095"),
        (["200",    "0"],    "Secondary",   "0"),
        (["200", "4095"],    "Secondary",   "4095"),
   ])
    def test_pvlan_association_del_validate_vlan_id_range(self, basic_suite, test_args, invalid_arg, invalid_vid):
        (config, show, db) = basic_suite
        ctx_obj = {'db': db['config_db']}
        result = self.runner.invoke(config.config.commands['pvlan'].commands['association'].commands['del'], test_args, obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Invalid {} VLAN ID {} (1-4094)'.format(invalid_arg, invalid_vid)

    def test_pvlan_association_not_allow_remove_associated_vlan(self, basic_suite):
        (config, show, db) = basic_suite
        ctx_obj = {'db': db['config_db']}
        primary_vid = "200"
        secondary_vid = "201"
        self.runner.invoke(config.config.commands['vlan'].commands['add'], [primary_vid, "primary"], obj=ctx_obj)
        assert True == self.is_cfgdb_vlan_exist(db, primary_vid)
        self.runner.invoke(config.config.commands['vlan'].commands['add'], [secondary_vid, "community"], obj=ctx_obj)
        assert True == self.is_cfgdb_vlan_exist(db, secondary_vid)

        self.runner.invoke(config.config.commands['pvlan'].commands['association'].commands['add'], [primary_vid, secondary_vid], obj=ctx_obj)
        assert True == self.is_cfgdb_pvlan_association_exist(db, primary_vid, secondary_vid)

        result = self.runner.invoke(config.config.commands['vlan'].commands['del'], [primary_vid], obj=ctx_obj)
        assert result.exit_code == 2
        assert self.get_err_str(result.output) == 'Not allow to remove Vlan{} which still associated with other private VLAN.'.format(primary_vid)
        assert True == self.is_cfgdb_vlan_exist(db, primary_vid)

        self.runner.invoke(config.config.commands['pvlan'].commands['association'].commands['del'], [primary_vid, secondary_vid], obj=ctx_obj)
        assert False == self.is_cfgdb_pvlan_association_exist(db, primary_vid, secondary_vid)

        result = self.runner.invoke(config.config.commands['vlan'].commands['del'], [primary_vid], obj=ctx_obj)
        assert result.exit_code == 0
        assert False == self.is_cfgdb_vlan_exist(db, primary_vid)
        result = self.runner.invoke(config.config.commands['vlan'].commands['del'], [secondary_vid], obj=ctx_obj)
        assert result.exit_code == 0
        assert False == self.is_cfgdb_vlan_exist(db, primary_vid)

    @classmethod
    def teardown_class(cls):
        # print("TEARDOWN")
        pass