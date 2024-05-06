"""test_set_user_variables.py - Test script for the set_user_variables function."""

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

from guicalculator.calculator.calculatordata.functions.setuservar import set_user_variables
from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class SetUserVariablesTest(SetupCalculatorDataTest):

    def test_set_user_variables(self):
        """Test the set_user_variables function."""

        """
        We have already validated (in test_validate_symbol_and_func) that all 
        the valid symbols and functions should be accepted, so this test just 
        checks that basic functionality is working.
        """
        test_data = [
            {
                "case": "No existing variables",
                "current": {"calc": [], "inpt": "", "vars": {}},
                "params": {"user_variables": {"a": Decimal("1"), "b": Decimal("2")}},
                "ending": {
                    "calc": [],
                    "inpt": "",
                    "vars": {"a": Decimal("1"), "b": Decimal("2")},
                },
            },
            {
                "case": "Existing variables",
                "current": {
                    "calc": [],
                    "inpt": "",
                    "vars": {"a": Decimal("1"), "b": Decimal("2")},
                },
                "params": {"user_variables": {"c": Decimal("3"), "d": Decimal("4")}},
                "ending": {
                    "calc": [],
                    "inpt": "",
                    "vars": {"c": Decimal("3"), "d": Decimal("4")},
                },
            },
            {
                "case": "Existing variables overwritten with blank",
                "current": {
                    "calc": [],
                    "inpt": "",
                    "vars": {"a": Decimal("1"), "b": Decimal("2")},
                },
                "params": {"user_variables": {}},
                "ending": {
                    "calc": [],
                    "inpt": "",
                    "vars": {},
                },
            },
        ]

        for data in test_data:
            with self.subTest(msg="set_user_variables: " + data["case"]):
                self.run_basic_test(
                    func=set_user_variables,
                    cur_vals=data["current"],
                    params={"self": self.calc_data, **data["params"]},
                    end_vals=data["ending"],
                )

    def test_set_user_variables_invalid_input(self):
        """Test the set_user_variables function with invalid input."""

        test_data = [
            {
                "case": "Variable has no name",
                "current": {"calc": [], "inpt": "", "vars": {}},
                "params": {"user_variables": {"": Decimal(123)}},
                "result": TypeError,
            },
            {
                "case": "Variable name is wrong data type",
                "current": {"calc": [], "inpt": "", "vars": {}},
                "params": {"user_variables": {123: Decimal(123)}},
                "result": TypeError,
            },
            {
                "case": "Invalid variable name (not an identifier)",
                "current": {"calc": [], "inpt": "", "vars": {}},
                "params": {"user_variables": {"a-b": Decimal(123)}},
                "result": TypeError,
            },
            {
                "case": "Variable name is a reserved word",
                "current": {"calc": [], "inpt": "", "vars": {}},
                "params": {"user_variables": {"def": Decimal(123)}},
                "result": TypeError,
            },
            {
                "case": "Overwrite default variable",
                "current": {"calc": [], "inpt": "", "vars": {}},
                "params": {"user_variables": {"e": Decimal(123)}},
                "result": TypeError,
            },
            {
                "case": "No value for variable",
                "current": {"calc": [], "inpt": "", "vars": {}},
                "params": {"user_variables": {"x": None}},
                "result": TypeError,
            },
            {
                "case": "Invalid value for variable (not Decimal)",
                "current": {"calc": [], "inpt": "", "vars": {}},
                "params": {"user_variables": {"x": "abcdefg"}},
                "result": TypeError,
            },
            {
                "case": "Invalid parameter (not a dict[str, Decimal])",
                "current": {"calc": [], "inpt": "", "vars": {}},
                "params": {"user_variables": "bob"},
                "result": AttributeError,
            },
            {
                "case": "Injection attack #1",
                "current": {"calc": [], "inpt": "", "vars": {}},
                "params": {"user_variables": "__import__('os').system('dir')"},
                "result": AttributeError,
            },
            {
                "case": "Injection attack #2",
                "current": {"calc": [], "inpt": "", "vars": {}},
                "params": {"user_variables": lambda: __import__("os").system("dir")},
                "result": AttributeError,
            },
        ]
        for data in test_data:
            with self.subTest(msg="set_user_variables: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=set_user_variables,
                        cur_vals=data["current"],
                        params={"self": self.calc_data, **data["params"]},
                        end_vals=data["current"],
                    )


if __name__ == "__main__":
    unittest.main()
