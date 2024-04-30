"""
validate_user_var.py - Validate that nothing improper is in user_variables.
"""

"""
Copyright (c) 2024 Thomas Brotherton

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


import keyword
from decimal import Decimal

from ..globals import DEFAULT_VARIABLES, VariablesType
from .logwrapper import plain_wrapper


@plain_wrapper
def validate_user_var(nam: str | None, val: Decimal | None) -> None:
    """
    validate_user_vars - Validate that nothing improper is in a single user variable

    Parameters
    ----------
    nam : str | None
        The variable name (the key in VariablesType)
    val : Decimal | None
        The variable value (the value in VariablesType)

    Raises
    ------
    TypeError
        Used for custom errors, message indicates what the specific error was.
    """

    if not nam:
        raise TypeError(f"Variable has no name")

    if type(nam) != str:
        raise TypeError(f"Variable name is wrong data type: {nam!r}")

    if not nam.isidentifier():
        raise TypeError(f"Invalid variable name: {nam!r}")

    if keyword.iskeyword(nam):
        raise TypeError(f"Variable name is a reserved word: {nam!r}")

    if nam in DEFAULT_VARIABLES.keys():
        raise TypeError(f"Attempt to overwrite default variable: {nam!r}")

    if val is None:
        raise TypeError(f"No value for variable: {nam!r}")

    if type(val) != Decimal:
        raise TypeError(f"Invalid value for variable: {nam!r}: {val!r}")


@plain_wrapper
def validate_user_vars(user_variables: VariablesType):
    """
    validate_user_vars  - Validate that nothing improper is in user_variables

    Parameters
    ----------
    user_variables : VariablesType
        variables to validate
    """
    for nam, val in user_variables.items():
        validate_user_var(nam, val)
