"""
processbutton.py - The set_user_variables function, validates the input user 
variables and then stores them in CalculatorData.
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

from ....globals import VariablesType
from ...logwrapper import object_wrapper
from ...validate_user_var import validate_user_vars
from ..calculatordata import CalculatorData


@object_wrapper
def set_user_variables(self: CalculatorData, user_variables: VariablesType) -> None:
    """
    set_user_variables - Set _user_variables
    """

    # this validation is duplicated from uservarseditfrm
    # but I don't want to leave the api vulnerable here
    # or lose the ability to identify the problem row there
    validate_user_vars(user_variables)

    self._user_variables = user_variables
