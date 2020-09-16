import os
import sys

import mock
import click
import pytest

import mock_tables.dbconnector

import sonic_device_util
from swsssdk import ConfigDBConnector
from swsssdk import SonicV2Connector

test_path = os.path.dirname(os.path.abspath(__file__))
modules_path = os.path.dirname(test_path)
sys.path.insert(0, modules_path)
scripts_path = os.path.join(modules_path, "scripts")

@pytest.fixture(scope = 'module')
def get_cmd_module():
    mock_version_info = {'asic_type': 'broadcom'}
    sonic_device_util.get_sonic_version_info = mock.MagicMock(return_value = mock_version_info)

    import config.main as config
    import show.main as show

    config_db = ConfigDBConnector()
    config_db.connect()

    config.config_db = config_db
    show.config_db = config_db

    app_db = ConfigDBConnector()
    app_db.db_connect(app_db.APPL_DB)

    state_db = ConfigDBConnector()
    state_db.db_connect(state_db.STATE_DB)

    db_obj = {'config_db': config_db, 'app_db': app_db, 'state_db': state_db}

    return (config, show, db_obj)
