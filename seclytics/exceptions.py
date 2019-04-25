class InvalidAccessToken(Exception):
    """We got a 401 Unauthorized"""

class OverQuota(Exception):
    """We got a 429 Too Many Requests"""

class ApiError(Exception):
    """General API Error"""
