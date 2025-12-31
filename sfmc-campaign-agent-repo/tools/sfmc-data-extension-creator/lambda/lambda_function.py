"""AWS Lambda handler shim.

This module allows handler configuration of "lambda_function.lambda_handler" while
keeping the implementation in handler.py.
"""

from handler import lambda_handler

__all__ = ["lambda_handler"]
