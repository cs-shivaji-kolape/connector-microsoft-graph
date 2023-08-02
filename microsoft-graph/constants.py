""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

CLIENT_CREDENTIALS = 'client_credentials'


SCOPE = 'https://graph.microsoft.com/.default'

RESOURCE = "https://graph.microsoft.com"
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
