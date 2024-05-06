"""test_get_user_variables.py - Test script for the get_user_variables function."""

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

import unittest
from decimal import Decimal

from guicalculator.calculator.calculatordata.functions.getuservar import (
    get_user_variables,
)
from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class GetUserVariablesTest(SetupCalculatorDataTest):

    def test_get_user_variables(self):
        """Test the get_user_variables function."""

        """
        We have already validated (in test_validate_symbol_and_func) that all 
        the valid symbols and functions should be accepted, so this test just 
        checks that basic functionality is working.
        """
        test_data = [
            {
                "case": "No variables",
                "current": {"calc": [], "inpt": "", "vars": {}},
                "ending": {"calc": [], "inpt": "", "vars": {}},
                "result": {},
            },
            {
                "case": "Variables",
                "current": {
                    "calc": [],
                    "inpt": "",
                    "vars": {"a": Decimal("1"), "b": Decimal("2")},
                },
                "ending": {
                    "calc": [],
                    "inpt": "",
                    "vars": {"a": Decimal("1"), "b": Decimal("2")},
                },
                "result": {"a": Decimal("1"), "b": Decimal("2")},
            },
        ]

        for data in test_data:
            with self.subTest(msg="get_user_variables: " + data["case"]):
                res = self.run_basic_test(
                    func=get_user_variables,
                    cur_vals=data["current"],
                    params={"self": self.calc_data},
                    end_vals=data["ending"],
                )
                self.assertEqual(res, data["result"])

    # get_user_variables doesn't take input, so there isn't an invalid input check


if __name__ == "__main__":
    unittest.main()
