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
    ###################################
    # There are some functions will be executed immediately when import config/main.py.
    # Needs to replace those functions with mock functions to return mock data.
    mock_version_info = {'asic_type': 'broadcom'}
    sonic_device_util.get_sonic_version_info = mock.MagicMock(return_value = mock_version_info)

    # UtilHelper.get_platform_and_hwsku() spawns subprocess to get data from real redis-db.
    # It causes program hang when running unit tests, because the required data does not exist in redis-db.
    # Shall mock this function to solve hang issue.
    from utilities_common.util_base import UtilHelper
    mock_platform_and_hwsku = ("x86_64-accton_as7726_32x-r0", "Accton-AS7726-32X")
    UtilHelper.get_platform_and_hwsku = mock.MagicMock(return_value = mock_platform_and_hwsku)
    ###################################

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
