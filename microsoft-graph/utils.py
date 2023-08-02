""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('microsoft_graph')


def _list(user_list):
    if isinstance(user_list, str):
        user_list = user_list.replace(" ", "").split(",")
    elif isinstance(user_list, tuple):
        user_list = list(user_list)
    elif isinstance(user_list, list):
        user_list
    else:
        logger.error('Incorrect Input')
        raise ConnectorError('Incorrect Input')
    return user_list

