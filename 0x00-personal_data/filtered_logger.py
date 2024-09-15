#!/usr/bin/env python3
import re

def filter_datum(fields, redaction, message, separator):
    """Returns the log message with specified fields obfuscated"""
    return re.sub(r'({})=.+?{}'.format('|'.join(fields), separator), r'\1={}{}'.format(redaction, separator), message)
