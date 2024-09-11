# Edit the config_and_params.json file and add the necessary parameter values.
"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

import os
import sys
import json
import pytest
import logging
import importlib
from connectors.core.connector import ConnectorError

with open('tests/config_and_params.json', 'r') as file:
    params = json.load(file)

current_directory = os.path.dirname(__file__)
parent_directory = os.path.abspath(os.path.join(current_directory, os.pardir))
grandparent_directory = os.path.abspath(os.path.join(parent_directory, os.pardir))
sys.path.insert(0, str(grandparent_directory))

module_name = 'microsoft-graph_2_2_0.operations'
conn_operations_module = importlib.import_module(module_name)
operations = conn_operations_module.operations

with open('info.json', 'r') as file:
    info_json = json.load(file)

logger = logging.getLogger(__name__)


# To test with different configuration values, adjust the index in the list below.
@pytest.fixture(scope="module")
def valid_configuration():
    return params.get('config')[0]


@pytest.fixture(scope="module")
def valid_configuration_with_token(valid_configuration):
    config = valid_configuration.copy()
    try:
        operations['check_health'](config)
    except TypeError:
        connector_info = config['connector_info']
        operations['check_health'](config, connector_info)
    return config


@pytest.mark.checkhealth
def test_check_health_success(valid_configuration):
    config = valid_configuration.copy()
    try:
        result = operations['check_health'](config)
    except TypeError:
        connector_info = config['connector_info']
        result = operations['check_health'](config, connector_info)
    assert result


@pytest.mark.checkhealth
def test_check_health_invalid_client_secret(valid_configuration):
    invalid_config = valid_configuration.copy()
    invalid_config['client_secret'] = params.get('invalid_params')['password']
    with pytest.raises(ConnectorError):
        try:
            operations['check_health'](invalid_config)
        except TypeError:
            connector_info = invalid_config['connector_info']
            operations['check_health'](invalid_config, connector_info)


@pytest.mark.checkhealth
def test_check_health_invalid_tenant(valid_configuration):
    invalid_config = valid_configuration.copy()
    invalid_config['tenant'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        try:
            operations['check_health'](invalid_config)
        except TypeError:
            connector_info = invalid_config['connector_info']
            operations['check_health'](invalid_config, connector_info)


@pytest.mark.checkhealth
def test_check_health_invalid_resource(valid_configuration):
    invalid_config = valid_configuration.copy()
    invalid_config['resource'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        try:
            operations['check_health'](invalid_config)
        except TypeError:
            connector_info = invalid_config['connector_info']
            operations['check_health'](invalid_config, connector_info)


@pytest.mark.checkhealth
def test_check_health_invalid_client_id(valid_configuration):
    invalid_config = valid_configuration.copy()
    invalid_config['client_id'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        try:
            operations['check_health'](invalid_config)
        except TypeError:
            connector_info = invalid_config['connector_info']
            operations['check_health'](invalid_config, connector_info)


@pytest.mark.get_risky_users_list
@pytest.mark.parametrize("input_params", params['get_risky_users_list'])
def test_get_risky_users_list_success(valid_configuration_with_token, input_params):
    logger.info("params: {0}".format(input_params))
    assert operations['get_risky_users_list'](valid_configuration_with_token.copy(), input_params.copy())


# Ensure that the provided input_params yield the correct output schema, or adjust the index in the list below.
# Add logic for validating conditional_output_schema or if schema is other than dict.
@pytest.mark.get_risky_users_list
@pytest.mark.schema_validation
def test_validate_get_risky_users_list_output_schema(valid_configuration_with_token):
    input_params = params.get('get_risky_users_list')[0].copy()
    schema = {}
    for operation in info_json.get("operations"):
        if operation.get('operation') == 'get_risky_users_list':
            if operation.get('conditional_output_schema'):
                pytest.skip("Skipping test because conditional_output_schema is not supported.")
            else:
                schema = operation.get('output_schema')
            break
    logger.info("output_schema: {0}".format(schema))
    resp = operations['get_risky_users_list'](valid_configuration_with_token.copy(), input_params)
    if isinstance(resp, dict) and isinstance(schema, dict):
        assert resp.keys() == schema.keys()
    else:
        pytest.skip("Skipping test because output_schema is not a dict.")


@pytest.mark.get_risky_user_details
@pytest.mark.parametrize("input_params", params['get_risky_user_details'])
def test_get_risky_user_details_success(valid_configuration_with_token, input_params):
    logger.info("params: {0}".format(input_params))
    assert operations['get_risky_user_details'](valid_configuration_with_token.copy(), input_params.copy())


# Ensure that the provided input_params yield the correct output schema, or adjust the index in the list below.
# Add logic for validating conditional_output_schema or if schema is other than dict.
@pytest.mark.get_risky_user_details
@pytest.mark.schema_validation
def test_validate_get_risky_user_details_output_schema(valid_configuration_with_token):
    input_params = params.get('get_risky_user_details')[0].copy()
    schema = {}
    for operation in info_json.get("operations"):
        if operation.get('operation') == 'get_risky_user_details':
            if operation.get('conditional_output_schema'):
                pytest.skip("Skipping test because conditional_output_schema is not supported.")
            else:
                schema = operation.get('output_schema')
            break
    logger.info("output_schema: {0}".format(schema))
    resp = operations['get_risky_user_details'](valid_configuration_with_token.copy(), input_params)
    if isinstance(resp, dict) and isinstance(schema, dict):
        assert resp.keys() == schema.keys()
    else:
        pytest.skip("Skipping test because output_schema is not a dict.")


@pytest.mark.get_risky_user_details
def test_get_risky_user_details_invalid_risk_id(valid_configuration_with_token):
    input_params = params.get('get_risky_user_details')[0].copy()
    input_params['risk_id'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['get_risky_user_details'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.get_all_security_alerts
@pytest.mark.parametrize("input_params", params['get_all_security_alerts'])
def test_get_all_security_alerts_success(valid_configuration_with_token, input_params):
    logger.info("params: {0}".format(input_params))
    assert operations['get_all_security_alerts'](valid_configuration_with_token.copy(), input_params.copy())


# Ensure that the provided input_params yield the correct output schema, or adjust the index in the list below.
# Add logic for validating conditional_output_schema or if schema is other than dict.
@pytest.mark.get_all_security_alerts
@pytest.mark.schema_validation
def test_validate_get_all_security_alerts_output_schema(valid_configuration_with_token):
    input_params = params.get('get_all_security_alerts')[0].copy()
    schema = {}
    for operation in info_json.get("operations"):
        if operation.get('operation') == 'get_all_security_alerts':
            if operation.get('conditional_output_schema'):
                pytest.skip("Skipping test because conditional_output_schema is not supported.")
            else:
                schema = operation.get('output_schema')
            break
    logger.info("output_schema: {0}".format(schema))
    resp = operations['get_all_security_alerts'](valid_configuration_with_token.copy(), input_params)
    if isinstance(resp, dict) and isinstance(schema, dict):
        assert resp.keys() == schema.keys()
    else:
        pytest.skip("Skipping test because output_schema is not a dict.")


@pytest.mark.get_all_security_alerts
def test_get_all_security_alerts_invalid_assigned_to(valid_configuration_with_token):
    input_params = params.get('get_all_security_alerts')[0].copy()
    input_params['assigned_to'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['get_all_security_alerts'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.get_all_security_alerts
def test_get_all_security_alerts_invalid_skip(valid_configuration_with_token):
    input_params = params.get('get_all_security_alerts')[0].copy()
    input_params['skip'] = params.get('invalid_params')['integer']
    with pytest.raises(ConnectorError):
        operations['get_all_security_alerts'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.get_all_security_alerts
def test_get_all_security_alerts_invalid_vendor(valid_configuration_with_token):
    input_params = params.get('get_all_security_alerts')[0].copy()
    input_params['vendor'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['get_all_security_alerts'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.get_all_security_alerts
def test_get_all_security_alerts_invalid_provider(valid_configuration_with_token):
    input_params = params.get('get_all_security_alerts')[0].copy()
    input_params['provider'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['get_all_security_alerts'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.get_all_security_alerts
def test_get_all_security_alerts_invalid_top(valid_configuration_with_token):
    input_params = params.get('get_all_security_alerts')[0].copy()
    input_params['top'] = params.get('invalid_params')['integer']
    with pytest.raises(ConnectorError):
        operations['get_all_security_alerts'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.get_security_alert
@pytest.mark.parametrize("input_params", params['get_security_alert'])
def test_get_security_alert_success(valid_configuration_with_token, input_params):
    logger.info("params: {0}".format(input_params))
    assert operations['get_security_alert'](valid_configuration_with_token.copy(), input_params.copy())


# Ensure that the provided input_params yield the correct output schema, or adjust the index in the list below.
# Add logic for validating conditional_output_schema or if schema is other than dict.
@pytest.mark.get_security_alert
@pytest.mark.schema_validation
def test_validate_get_security_alert_output_schema(valid_configuration_with_token):
    input_params = params.get('get_security_alert')[0].copy()
    schema = {}
    for operation in info_json.get("operations"):
        if operation.get('operation') == 'get_security_alert':
            if operation.get('conditional_output_schema'):
                pytest.skip("Skipping test because conditional_output_schema is not supported.")
            else:
                schema = operation.get('output_schema')
            break
    logger.info("output_schema: {0}".format(schema))
    resp = operations['get_security_alert'](valid_configuration_with_token.copy(), input_params)
    if isinstance(resp, dict) and isinstance(schema, dict):
        assert resp.keys() == schema.keys()
    else:
        pytest.skip("Skipping test because output_schema is not a dict.")


@pytest.mark.get_security_alert
def test_get_security_alert_invalid_alert_id(valid_configuration_with_token):
    input_params = params.get('get_security_alert')[0].copy()
    input_params['alert_id'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['get_security_alert'](valid_configuration_with_token.copy(), input_params)


x


@pytest.mark.update_security_alert
@pytest.mark.parametrize("input_params", params['update_security_alert'])
def test_update_security_alert_success(valid_configuration_with_token, input_params):
    logger.info("params: {0}".format(input_params))
    assert operations['update_security_alert'](valid_configuration_with_token.copy(), input_params.copy())


# Ensure that the provided input_params yield the correct output schema, or adjust the index in the list below.
# Add logic for validating conditional_output_schema or if schema is other than dict.
@pytest.mark.update_security_alert
@pytest.mark.schema_validation
def test_validate_update_security_alert_output_schema(valid_configuration_with_token):
    input_params = params.get('update_security_alert')[0].copy()
    schema = {}
    for operation in info_json.get("operations"):
        if operation.get('operation') == 'update_security_alert':
            if operation.get('conditional_output_schema'):
                pytest.skip("Skipping test because conditional_output_schema is not supported.")
            else:
                schema = operation.get('output_schema')
            break
    logger.info("output_schema: {0}".format(schema))
    resp = operations['update_security_alert'](valid_configuration_with_token.copy(), input_params)
    if isinstance(resp, dict) and isinstance(schema, dict):
        assert resp.keys() == schema.keys()
    else:
        pytest.skip("Skipping test because output_schema is not a dict.")


@pytest.mark.update_security_alert
def test_update_security_alert_invalid_subProvider(valid_configuration_with_token):
    input_params = params.get('update_security_alert')[0].copy()
    input_params['subProvider'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['update_security_alert'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.update_security_alert
def test_update_security_alert_invalid_alert_id(valid_configuration_with_token):
    input_params = params.get('update_security_alert')[0].copy()
    input_params['alert_id'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['update_security_alert'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.update_security_alert
def test_update_security_alert_invalid_tags(valid_configuration_with_token):
    input_params = params.get('update_security_alert')[0].copy()
    input_params['tags'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['update_security_alert'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.update_security_alert
def test_update_security_alert_invalid_assigned_to(valid_configuration_with_token):
    input_params = params.get('update_security_alert')[0].copy()
    input_params['assigned_to'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['update_security_alert'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.update_security_alert
def test_update_security_alert_invalid_vendor(valid_configuration_with_token):
    input_params = params.get('update_security_alert')[0].copy()
    input_params['vendor'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['update_security_alert'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.update_security_alert
def test_update_security_alert_invalid_providerVersion(valid_configuration_with_token):
    input_params = params.get('update_security_alert')[0].copy()
    input_params['providerVersion'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['update_security_alert'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.update_security_alert
def test_update_security_alert_invalid_provider(valid_configuration_with_token):
    input_params = params.get('update_security_alert')[0].copy()
    input_params['provider'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['update_security_alert'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.add_comment_on_security_alert
@pytest.mark.parametrize("input_params", params['add_comment_on_security_alert'])
def test_add_comment_on_security_alert_success(valid_configuration_with_token, input_params):
    logger.info("params: {0}".format(input_params))
    assert operations['add_comment_on_security_alert'](valid_configuration_with_token.copy(), input_params.copy())


# Ensure that the provided input_params yield the correct output schema, or adjust the index in the list below.
# Add logic for validating conditional_output_schema or if schema is other than dict.
@pytest.mark.add_comment_on_security_alert
@pytest.mark.schema_validation
def test_validate_add_comment_on_security_alert_output_schema(valid_configuration_with_token):
    input_params = params.get('add_comment_on_security_alert')[0].copy()
    schema = {}
    for operation in info_json.get("operations"):
        if operation.get('operation') == 'add_comment_on_security_alert':
            if operation.get('conditional_output_schema'):
                pytest.skip("Skipping test because conditional_output_schema is not supported.")
            else:
                schema = operation.get('output_schema')
            break
    logger.info("output_schema: {0}".format(schema))
    resp = operations['add_comment_on_security_alert'](valid_configuration_with_token.copy(), input_params)
    if isinstance(resp, dict) and isinstance(schema, dict):
        assert resp.keys() == schema.keys()
    else:
        pytest.skip("Skipping test because output_schema is not a dict.")


@pytest.mark.add_comment_on_security_alert
def test_add_comment_on_security_alert_invalid_comment(valid_configuration_with_token):
    input_params = params.get('add_comment_on_security_alert')[0].copy()
    input_params['comment'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['add_comment_on_security_alert'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.add_comment_on_security_alert
def test_add_comment_on_security_alert_invalid_alert_id(valid_configuration_with_token):
    input_params = params.get('add_comment_on_security_alert')[0].copy()
    input_params['alert_id'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['add_comment_on_security_alert'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.get_groups
@pytest.mark.parametrize("input_params", params['get_groups'])
def test_get_groups_success(valid_configuration_with_token, input_params):
    logger.info("params: {0}".format(input_params))
    assert operations['get_groups'](valid_configuration_with_token.copy(), input_params.copy())


# Ensure that the provided input_params yield the correct output schema, or adjust the index in the list below.
# Add logic for validating conditional_output_schema or if schema is other than dict.
@pytest.mark.get_groups
@pytest.mark.schema_validation
def test_validate_get_groups_output_schema(valid_configuration_with_token):
    input_params = params.get('get_groups')[0].copy()
    schema = {}
    for operation in info_json.get("operations"):
        if operation.get('operation') == 'get_groups':
            if operation.get('conditional_output_schema'):
                pytest.skip("Skipping test because conditional_output_schema is not supported.")
            else:
                schema = operation.get('output_schema')
            break
    logger.info("output_schema: {0}".format(schema))
    resp = operations['get_groups'](valid_configuration_with_token.copy(), input_params)
    if isinstance(resp, dict) and isinstance(schema, dict):
        assert resp.keys() == schema.keys()
    else:
        pytest.skip("Skipping test because output_schema is not a dict.")


@pytest.mark.get_group_users
@pytest.mark.parametrize("input_params", params['get_group_users'])
def test_get_group_users_success(valid_configuration_with_token, input_params):
    logger.info("params: {0}".format(input_params))
    assert operations['get_group_users'](valid_configuration_with_token.copy(), input_params.copy())


# Ensure that the provided input_params yield the correct output schema, or adjust the index in the list below.
# Add logic for validating conditional_output_schema or if schema is other than dict.
@pytest.mark.get_group_users
@pytest.mark.schema_validation
def test_validate_get_group_users_output_schema(valid_configuration_with_token):
    input_params = params.get('get_group_users')[0].copy()
    schema = {}
    for operation in info_json.get("operations"):
        if operation.get('operation') == 'get_group_users':
            if operation.get('conditional_output_schema'):
                pytest.skip("Skipping test because conditional_output_schema is not supported.")
            else:
                schema = operation.get('output_schema')
            break
    logger.info("output_schema: {0}".format(schema))
    resp = operations['get_group_users'](valid_configuration_with_token.copy(), input_params)
    if isinstance(resp, dict) and isinstance(schema, dict):
        assert resp.keys() == schema.keys()
    else:
        pytest.skip("Skipping test because output_schema is not a dict.")


@pytest.mark.get_group_users
def test_get_group_users_invalid_group_id(valid_configuration_with_token):
    input_params = params.get('get_group_users')[0].copy()
    input_params['group_id'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['get_group_users'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.search_message
@pytest.mark.parametrize("input_params", params['search_message'])
def test_search_message_success(valid_configuration_with_token, input_params):
    logger.info("params: {0}".format(input_params))
    assert operations['search_message'](valid_configuration_with_token.copy(), input_params.copy())


# Ensure that the provided input_params yield the correct output schema, or adjust the index in the list below.
# Add logic for validating conditional_output_schema or if schema is other than dict.
@pytest.mark.search_message
@pytest.mark.schema_validation
def test_validate_search_message_output_schema(valid_configuration_with_token):
    input_params = params.get('search_message')[0].copy()
    schema = {}
    for operation in info_json.get("operations"):
        if operation.get('operation') == 'search_message':
            if operation.get('conditional_output_schema'):
                pytest.skip("Skipping test because conditional_output_schema is not supported.")
            else:
                schema = operation.get('output_schema')
            break
    logger.info("output_schema: {0}".format(schema))
    resp = operations['search_message'](valid_configuration_with_token.copy(), input_params)
    if isinstance(resp, dict) and isinstance(schema, dict):
        assert resp.keys() == schema.keys()
    else:
        pytest.skip("Skipping test because output_schema is not a dict.")


@pytest.mark.search_message
def test_search_message_invalid_skip(valid_configuration_with_token):
    input_params = params.get('search_message')[0].copy()
    input_params['skip'] = params.get('invalid_params')['integer']
    with pytest.raises(ConnectorError):
        operations['search_message'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.search_message
def test_search_message_invalid_size(valid_configuration_with_token):
    input_params = params.get('search_message')[0].copy()
    input_params['size'] = params.get('invalid_params')['integer']
    with pytest.raises(ConnectorError):
        operations['search_message'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.search_message
def test_search_message_invalid_subject(valid_configuration_with_token):
    input_params = params.get('search_message')[0].copy()
    input_params['subject'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['search_message'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.search_message
def test_search_message_invalid_user_list(valid_configuration_with_token):
    input_params = params.get('search_message')[0].copy()
    input_params['user_list'] = params.get('invalid_params')['textarea']
    with pytest.raises(ConnectorError):
        operations['search_message'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.del_message
@pytest.mark.parametrize("input_params", params['del_message'])
def test_del_message_success(valid_configuration_with_token, input_params):
    logger.info("params: {0}".format(input_params))
    assert operations['del_message'](valid_configuration_with_token.copy(), input_params.copy())


# Ensure that the provided input_params yield the correct output schema, or adjust the index in the list below.
# Add logic for validating conditional_output_schema or if schema is other than dict.
@pytest.mark.del_message
@pytest.mark.schema_validation
def test_validate_del_message_output_schema(valid_configuration_with_token):
    input_params = params.get('del_message')[0].copy()
    schema = {}
    for operation in info_json.get("operations"):
        if operation.get('operation') == 'del_message':
            if operation.get('conditional_output_schema'):
                pytest.skip("Skipping test because conditional_output_schema is not supported.")
            else:
                schema = operation.get('output_schema')
            break
    logger.info("output_schema: {0}".format(schema))
    resp = operations['del_message'](valid_configuration_with_token.copy(), input_params)
    if isinstance(resp, dict) and isinstance(schema, dict):
        assert resp.keys() == schema.keys()
    else:
        pytest.skip("Skipping test because output_schema is not a dict.")


@pytest.mark.del_message
def test_del_message_invalid_user_id(valid_configuration_with_token):
    input_params = params.get('del_message')[0].copy()
    input_params['user_id'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['del_message'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.del_message
def test_del_message_invalid_message_id(valid_configuration_with_token):
    input_params = params.get('del_message')[0].copy()
    input_params['message_id'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['del_message'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.del_message_bulk
@pytest.mark.parametrize("input_params", params['del_message_bulk'])
def test_del_message_bulk_success(valid_configuration_with_token, input_params):
    logger.info("params: {0}".format(input_params))
    assert operations['del_message_bulk'](valid_configuration_with_token.copy(), input_params.copy())


# Ensure that the provided input_params yield the correct output schema, or adjust the index in the list below.
# Add logic for validating conditional_output_schema or if schema is other than dict.
@pytest.mark.del_message_bulk
@pytest.mark.schema_validation
def test_validate_del_message_bulk_output_schema(valid_configuration_with_token):
    input_params = params.get('del_message_bulk')[0].copy()
    schema = {}
    for operation in info_json.get("operations"):
        if operation.get('operation') == 'del_message_bulk':
            if operation.get('conditional_output_schema'):
                pytest.skip("Skipping test because conditional_output_schema is not supported.")
            else:
                schema = operation.get('output_schema')
            break
    logger.info("output_schema: {0}".format(schema))
    resp = operations['del_message_bulk'](valid_configuration_with_token.copy(), input_params)
    if isinstance(resp, dict) and isinstance(schema, dict):
        assert resp.keys() == schema.keys()
    else:
        pytest.skip("Skipping test because output_schema is not a dict.")


@pytest.mark.del_message_bulk
def test_del_message_bulk_invalid_user_list(valid_configuration_with_token):
    input_params = params.get('del_message_bulk')[0].copy()
    input_params['user_list'] = params.get('invalid_params')['json']
    with pytest.raises(ConnectorError):
        operations['del_message_bulk'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.revoke_user_sessions
@pytest.mark.parametrize("input_params", params['revoke_user_sessions'])
def test_revoke_user_sessions_success(valid_configuration_with_token, input_params):
    logger.info("params: {0}".format(input_params))
    assert operations['revoke_user_sessions'](valid_configuration_with_token.copy(), input_params.copy())


# Ensure that the provided input_params yield the correct output schema, or adjust the index in the list below.
# Add logic for validating conditional_output_schema or if schema is other than dict.
@pytest.mark.revoke_user_sessions
@pytest.mark.schema_validation
def test_validate_revoke_user_sessions_output_schema(valid_configuration_with_token):
    input_params = params.get('revoke_user_sessions')[0].copy()
    schema = {}
    for operation in info_json.get("operations"):
        if operation.get('operation') == 'revoke_user_sessions':
            if operation.get('conditional_output_schema'):
                pytest.skip("Skipping test because conditional_output_schema is not supported.")
            else:
                schema = operation.get('output_schema')
            break
    logger.info("output_schema: {0}".format(schema))
    resp = operations['revoke_user_sessions'](valid_configuration_with_token.copy(), input_params)
    if isinstance(resp, dict) and isinstance(schema, dict):
        assert resp.keys() == schema.keys()
    else:
        pytest.skip("Skipping test because output_schema is not a dict.")


@pytest.mark.revoke_user_sessions
def test_revoke_user_sessions_invalid_user(valid_configuration_with_token):
    input_params = params.get('revoke_user_sessions')[0].copy()
    input_params['user'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['revoke_user_sessions'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.get_all_named_locations
@pytest.mark.parametrize("input_params", params['get_all_named_locations'])
def test_get_all_named_locations_success(valid_configuration_with_token, input_params):
    logger.info("params: {0}".format(input_params))
    assert operations['get_all_named_locations'](valid_configuration_with_token.copy(), input_params.copy())


# Ensure that the provided input_params yield the correct output schema, or adjust the index in the list below.
# Add logic for validating conditional_output_schema or if schema is other than dict.
@pytest.mark.get_all_named_locations
@pytest.mark.schema_validation
def test_validate_get_all_named_locations_output_schema(valid_configuration_with_token):
    input_params = params.get('get_all_named_locations')[0].copy()
    schema = {}
    for operation in info_json.get("operations"):
        if operation.get('operation') == 'get_all_named_locations':
            if operation.get('conditional_output_schema'):
                pytest.skip("Skipping test because conditional_output_schema is not supported.")
            else:
                schema = operation.get('output_schema')
            break
    logger.info("output_schema: {0}".format(schema))
    resp = operations['get_all_named_locations'](valid_configuration_with_token.copy(), input_params)
    if isinstance(resp, dict) and isinstance(schema, dict):
        assert resp.keys() == schema.keys()
    else:
        pytest.skip("Skipping test because output_schema is not a dict.")


@pytest.mark.get_all_named_locations
def test_get_all_named_locations_invalid_name(valid_configuration_with_token):
    input_params = params.get('get_all_named_locations')[0].copy()
    input_params['name'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['get_all_named_locations'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.get_all_named_locations
def test_get_all_named_locations_invalid_skip(valid_configuration_with_token):
    input_params = params.get('get_all_named_locations')[0].copy()
    input_params['skip'] = params.get('invalid_params')['integer']
    with pytest.raises(ConnectorError):
        operations['get_all_named_locations'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.get_all_named_locations
def test_get_all_named_locations_invalid_size(valid_configuration_with_token):
    input_params = params.get('get_all_named_locations')[0].copy()
    input_params['size'] = params.get('invalid_params')['integer']
    with pytest.raises(ConnectorError):
        operations['get_all_named_locations'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.block_new_ips
@pytest.mark.parametrize("input_params", params['block_new_ips'])
def test_block_new_ips_success(valid_configuration_with_token, input_params):
    logger.info("params: {0}".format(input_params))
    assert operations['block_new_ips'](valid_configuration_with_token.copy(), input_params.copy())


# Ensure that the provided input_params yield the correct output schema, or adjust the index in the list below.
# Add logic for validating conditional_output_schema or if schema is other than dict.
@pytest.mark.block_new_ips
@pytest.mark.schema_validation
def test_validate_block_new_ips_output_schema(valid_configuration_with_token):
    input_params = params.get('block_new_ips')[0].copy()
    schema = {}
    for operation in info_json.get("operations"):
        if operation.get('operation') == 'block_new_ips':
            if operation.get('conditional_output_schema'):
                pytest.skip("Skipping test because conditional_output_schema is not supported.")
            else:
                schema = operation.get('output_schema')
            break
    logger.info("output_schema: {0}".format(schema))
    resp = operations['block_new_ips'](valid_configuration_with_token.copy(), input_params)
    if isinstance(resp, dict) and isinstance(schema, dict):
        assert resp.keys() == schema.keys()
    else:
        pytest.skip("Skipping test because output_schema is not a dict.")


@pytest.mark.block_new_ips
def test_block_new_ips_invalid_ipv6_ips(valid_configuration_with_token):
    input_params = params.get('block_new_ips')[0].copy()
    input_params['ipv6_ips'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['block_new_ips'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.block_new_ips
def test_block_new_ips_invalid_ipv4_ips(valid_configuration_with_token):
    input_params = params.get('block_new_ips')[0].copy()
    input_params['ipv4_ips'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['block_new_ips'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.block_new_ips
def test_block_new_ips_invalid_namedLocationUuid(valid_configuration_with_token):
    input_params = params.get('block_new_ips')[0].copy()
    input_params['namedLocationUuid'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['block_new_ips'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.unblock_new_ips
@pytest.mark.parametrize("input_params", params['unblock_new_ips'])
def test_unblock_new_ips_success(valid_configuration_with_token, input_params):
    logger.info("params: {0}".format(input_params))
    assert operations['unblock_new_ips'](valid_configuration_with_token.copy(), input_params.copy())


# Ensure that the provided input_params yield the correct output schema, or adjust the index in the list below.
# Add logic for validating conditional_output_schema or if schema is other than dict.
@pytest.mark.unblock_new_ips
@pytest.mark.schema_validation
def test_validate_unblock_new_ips_output_schema(valid_configuration_with_token):
    input_params = params.get('unblock_new_ips')[0].copy()
    schema = {}
    for operation in info_json.get("operations"):
        if operation.get('operation') == 'unblock_new_ips':
            if operation.get('conditional_output_schema'):
                pytest.skip("Skipping test because conditional_output_schema is not supported.")
            else:
                schema = operation.get('output_schema')
            break
    logger.info("output_schema: {0}".format(schema))
    resp = operations['unblock_new_ips'](valid_configuration_with_token.copy(), input_params)
    if isinstance(resp, dict) and isinstance(schema, dict):
        assert resp.keys() == schema.keys()
    else:
        pytest.skip("Skipping test because output_schema is not a dict.")


@pytest.mark.unblock_new_ips
def test_unblock_new_ips_invalid_ipv6_ips(valid_configuration_with_token):
    input_params = params.get('unblock_new_ips')[0].copy()
    input_params['ipv6_ips'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['unblock_new_ips'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.unblock_new_ips
def test_unblock_new_ips_invalid_ipv4_ips(valid_configuration_with_token):
    input_params = params.get('unblock_new_ips')[0].copy()
    input_params['ipv4_ips'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['unblock_new_ips'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.unblock_new_ips
def test_unblock_new_ips_invalid_namedLocationUuid(valid_configuration_with_token):
    input_params = params.get('unblock_new_ips')[0].copy()
    input_params['namedLocationUuid'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['unblock_new_ips'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.create_ip_range_location
@pytest.mark.parametrize("input_params", params['create_ip_range_location'])
def test_create_ip_range_location_success(valid_configuration_with_token, input_params):
    logger.info("params: {0}".format(input_params))
    assert operations['create_ip_range_location'](valid_configuration_with_token.copy(), input_params.copy())


# Ensure that the provided input_params yield the correct output schema, or adjust the index in the list below.
# Add logic for validating conditional_output_schema or if schema is other than dict.
@pytest.mark.create_ip_range_location
@pytest.mark.schema_validation
def test_validate_create_ip_range_location_output_schema(valid_configuration_with_token):
    input_params = params.get('create_ip_range_location')[0].copy()
    schema = {}
    for operation in info_json.get("operations"):
        if operation.get('operation') == 'create_ip_range_location':
            if operation.get('conditional_output_schema'):
                pytest.skip("Skipping test because conditional_output_schema is not supported.")
            else:
                schema = operation.get('output_schema')
            break
    logger.info("output_schema: {0}".format(schema))
    resp = operations['create_ip_range_location'](valid_configuration_with_token.copy(), input_params)
    if isinstance(resp, dict) and isinstance(schema, dict):
        assert resp.keys() == schema.keys()
    else:
        pytest.skip("Skipping test because output_schema is not a dict.")


@pytest.mark.create_ip_range_location
def test_create_ip_range_location_invalid_ipv6_ips(valid_configuration_with_token):
    input_params = params.get('create_ip_range_location')[0].copy()
    input_params['ipv6_ips'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['create_ip_range_location'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.create_ip_range_location
def test_create_ip_range_location_invalid_name(valid_configuration_with_token):
    input_params = params.get('create_ip_range_location')[0].copy()
    input_params['name'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['create_ip_range_location'](valid_configuration_with_token.copy(), input_params)


@pytest.mark.create_ip_range_location
def test_create_ip_range_location_invalid_ipv4_ips(valid_configuration_with_token):
    input_params = params.get('create_ip_range_location')[0].copy()
    input_params['ipv4_ips'] = params.get('invalid_params')['text']
    with pytest.raises(ConnectorError):
        operations['create_ip_range_location'](valid_configuration_with_token.copy(), input_params)

