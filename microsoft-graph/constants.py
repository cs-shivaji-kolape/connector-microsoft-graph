""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """


THREADS = 4
alerts_filter_map = {
    "vendor": "vendorInformation/vendor",
    "provider": "vendorInformation/provider",
    "severity": "severity",
    "search_from": "eventDateTime"
}
FEEDBACK = {
    "Unknown": "unknown",
    "True Positive": "truePositive",
    "False Positive": "falsePositive",
    "Benign Positive": "benignPositive"
}

STATUS = {
    "Unknown": "unknown",
    "New Alert": "newAlert",
    "In Progress": "inProgress",
    "Resolved": "resolved"
}

IPv4 = "#microsoft.graph.iPv4CidrRange"
IPv6 = "#microsoft.graph.iPv6CidrRange"
FIELDS = {
    "ID": "id",
    "Created Date Time": "createdDateTime",
    "Display Name": "displayName",
    "Modified Date Time": "modifiedDateTime"
}

RESOURCE = "https://graph.microsoft.com"
SCOPE = 'https://graph.microsoft.com/.default'
API_VERSION = 'v1.0'
AUTH_USING_APP = "Without a User - Application Permission"
AUTH_BEHALF_OF_USER = "On behalf of User - Delegate Permission"
REFRESH_TOKEN_FLAG = False
CONFIG_SUPPORTS_TOKEN = True
DEFAULT_REDIRECT_URL = 'https://localhost/myapp'

# grant types
CLIENT_CREDENTIALS = 'client_credentials'
AUTHORIZATION_CODE = 'authorization_code'
REFRESH_TOKEN = 'refresh_token'
