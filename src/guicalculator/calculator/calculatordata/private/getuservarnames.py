"""
getuservarnames.py - The get_user_variable_names function returns a list of
all defined variables.
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

from ....globals import DEFAULT_VARIABLES
from ...logwrapper import object_wrapper
from ..calculatordata import CalculatorData


@object_wrapper
def get_user_variable_names(
    self: CalculatorData, include_default: bool = True
) -> list[str]:
    """
    get_user_variable_names - Return a list of current variable names

    Validates that user variable names are string, doesn't check for keywords,
    invalid identifier, duplicating a default variable, etc as that is done
    by validate_user_var.

    Parameters
    ----------
    include_default : bool, optional
        include the default variables (e and pi), by default True

    Returns
    -------
    list[str]
        The variable names
    """

    varnames: list[str] = []

    if include_default:
        varnames.extend([*DEFAULT_VARIABLES.keys()])

    # double checking that variable names are str
    # default variables are defined in code so should be safe
    for var in self._user_variables.keys():
        if isinstance(var, str):
            varnames.append(var)
        else:
            raise ValueError(f"User variable name is not str: {var!r}")

    return varnames
