#!/usr/bin/env python3
"""
This module provides logging utilities to filter sensitive information
such as email addresses, social security numbers, and passwords.
It defines a `RedactingFormatter` class and a `filter_datum` function
to redact sensitive data in log messages.
"""

import logging
import re
from typing import List


def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    """
    Obfuscate specified fields in a log message.

    Args:
        fields (List[str]): The list of fields to redact.
        redaction (str): The string used to replace field values.
        message (str): The log message to filter.
        separator (str): The separator used in the log message.

    Returns:
        str: The log message with redacted fields.
    """
    return re.sub(r'({})=.+?{}'.format('|'.join(fields), separator),
                  r'\1={}{}'.format(redaction, separator), message)


class RedactingFormatter(logging.Formatter):
    """
    Formatter that redacts sensitive information in log messages.

    The fields to redact are passed as a list, and the message will
    have the values of those fields replaced with a redaction string.
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initialize the formatter with fields to redact.

        Args:
            fields (List[str]): The list of fields to redact in log messages.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record with sensitive fields redacted.

        """
        original_message = super().format(record)
        return filter_datum(
            self.fields, self.REDACTION, original_message, self.SEPARATOR)
