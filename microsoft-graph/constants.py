""" Copyright start
  Copyright (C) 2008 - 2024 Fortinet Inc.
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
DEFAULT_REDIRECT_URL = 'https://localhost/myapp'
AUTH_URL = 'https://login.microsoftonline.com'
# grant types
CLIENT_CREDENTIALS = 'client_credentials'
AUTHORIZATION_CODE = 'authorization_code'
REFRESH_TOKEN = 'refresh_token'
CERTIFICATE_BASED_AUTH_TYPE = "Certificate Based Authentication"