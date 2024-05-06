"""test_get_user_variable_names.py - Test script for the get_user_variable_names function."""

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

from guicalculator.calculator.calculatordata.private.getuservarnames import (
    get_user_variable_names,
)
from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class GetUserVariableNamesTest(SetupCalculatorDataTest):

    def test_get_user_variable_names(self):
        """Test the get_user_variable_names function."""

        test_data = [
            {
                "case": "No variables",
                "current": {"vars": {}},
                "params": {},
                "ending": {"vars": {}},
                "result": ["π", "e"],
            },
            {
                "case": "No variables, include_default False",
                "current": {"vars": {}},
                "params": {"include_default": False},
                "ending": {"vars": {}},
                "result": [],
            },
            {
                "case": "Variables",
                "current": {"vars": {"a": 1, "b": 2, "c": 3}},
                "params": {},
                "ending": {"vars": {"a": 1, "b": 2, "c": 3}},
                "result": ["π", "e", "a", "b", "c"],
            },
            {
                "case": "Cariables, include_default False",
                "current": {"vars": {"a": 1, "b": 2, "c": 3}},
                "params": {"include_default": False},
                "ending": {"vars": {"a": 1, "b": 2, "c": 3}},
                "result": ["a", "b", "c"],
            },
        ]

        for data in test_data:
            with self.subTest(msg="get_user_variable_names: " + data["case"]):
                result = self.run_basic_test(
                    func=get_user_variable_names,
                    cur_vals=data["current"],
                    params={"self": self.calc_data, **data["params"]},
                    end_vals=data["ending"],
                )
                self.assertEqual(result, data["result"])

    def test_get_user_variable_names_invalid_input(self):
        """Test the get_user_variable_names function with invalid input."""

        # this proc only checks to see if the variable name is a string
        # testing include_default is impossible because anything can be cast to boolean
        test_data = [
            {
                "case": "Invalid variables",
                "current": {"vars": {2: "a"}},
                "params": {},
                "ending": {"vars": {2: "a"}},
                "result": ValueError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="get_user_variable_names: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=get_user_variable_names,
                        cur_vals=data["current"],
                        params={"self": self.calc_data, **data["params"]},
                        end_vals=data["current"],
                    )


if __name__ == "__main__":
    unittest.main()
