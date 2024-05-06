"""test_validate_user_var.py - Test script for the validate_user_var function."""

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

from guicalculator.calculator import validate_user_var, validate_user_vars


class ValidateUserVarTest(unittest.TestCase):

    def test_validate_user_var(self):
        """Tests the validate_user_var function."""

        test_data = [
            {
                "case": "Variable > 0",
                "params": {"nam": "x", "val": Decimal("1234.56")},
            },
            {
                "case": "Variable = 0",
                "params": {"nam": "x", "val": Decimal("0")},
            },
            {
                "case": "Variable < 0",
                "params": {"nam": "x", "val": Decimal("-1234.56")},
            },
        ]

        for data in test_data:
            with self.subTest(msg="validate_user_var: " + data["case"]):
                validate_user_var(**data["params"])

    def test_validate_user_var_invalid_input(self):
        """Tests the validate_user_var function with invalid input."""

        test_data = [
            {
                "case": "No data input",
                "params": {"nam": None, "val": None},
                "result": TypeError,
            },
            {
                "case": "Variable name not str",
                "params": {"nam": 123, "val": None},
                "result": TypeError,
            },
            {
                "case": "Invalid identifier",
                "params": {"nam": "x-y", "val": None},
                "result": TypeError,
            },
            {
                "case": "Reserved word",
                "params": {"nam": "def", "val": None},
                "result": TypeError,
            },
            {
                "case": "Replace default variable",
                "params": {"nam": "e", "val": None},
                "result": TypeError,
            },
            {
                "case": "Valid name, no value",
                "params": {"nam": "x", "val": None},
                "result": TypeError,
            },
            {
                "case": "Valid name, non-Decimal value",
                "params": {"nam": "x", "val": 123.45},
                "result": TypeError,
            },
            {
                "case": "Injection attack 1",
                "params": {"nam": "x", "val": "__import__('os').system('dir')"},
                "result": TypeError,
            },
            {
                "case": "Injection attack 2",
                "params": {"nam": "x", "val": lambda: __import__("os").system("dir")},
                "result": TypeError,
            },
            {
                "case": "Injection attack 3",
                "params": {"nam": "__import__('os').system('dir')", "val": Decimal(1)},
                "result": TypeError,
            },
            {
                "case": "Injection attack 4",
                "params": {
                    "nam": lambda: __import__("os").system("dir"),
                    "val": Decimal(1),
                },
                "result": TypeError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="validate_user_var: " + data["case"]):
                with self.assertRaises(data["result"]):
                    validate_user_var(**data["params"])


class ValidateUserVarsTest(unittest.TestCase):

    def test_validate_user_vars(self):
        """Tests the validate_user_vars function."""

        test_data = [
            {
                "case": "Variable > 0",
                "params": {"user_variables": {"x": Decimal("1234.56")}},
            },
            {
                "case": "Variable = 0",
                "params": {"user_variables": {"x": Decimal("0")}},
            },
            {
                "case": "Variable < 0",
                "params": {"user_variables": {"x": Decimal("-1234.56")}},
            },
        ]

        for data in test_data:
            with self.subTest(msg="validate_user_vars: " + data["case"]):
                validate_user_vars(**data["params"])

    def test_validate_user_vars_invalid_input(self):
        """Tests the validate_user_vars function with invalid input."""

        test_data = [
            {
                "case": "No data input",
                "params": {"user_variables": {None: None}},
                "result": TypeError,
            },
            {
                "case": "Variable name not str",
                "params": {"user_variables": {123: None}},
                "result": TypeError,
            },
            {
                "case": "Invalid identifier",
                "params": {"user_variables": {"x-y": None}},
                "result": TypeError,
            },
            {
                "case": "Reserved word",
                "params": {"user_variables": {"def": None}},
                "result": TypeError,
            },
            {
                "case": "Replace default variable",
                "params": {"user_variables": {"e": None}},
                "result": TypeError,
            },
            {
                "case": "Valid name, no value",
                "params": {"user_variables": {"x": None}},
                "params": {"nam": "x", "val": None},
                "result": TypeError,
            },
            {
                "case": "Valid name, non-Decimal value",
                "params": {"user_variables": {"x": 123.45}},
                "result": TypeError,
            },
            {
                "case": "Injection attack 1",
                "params": {"user_variables": {"x": "__import__('os').system('dir')"}},
                "result": TypeError,
            },
            {
                "case": "Injection attack 2",
                "params": {
                    "user_variables": {"x": lambda: __import__("os").system("dir")}
                },
                "result": TypeError,
            },
            {
                "case": "Injection attack 3",
                "params": {
                    "user_variables": {"__import__('os').system('dir')": Decimal(1)}
                },
                "result": TypeError,
            },
            {
                "case": "Injection attack 4",
                "params": {
                    "user_variables": {
                        lambda: __import__("os").system("dir"): Decimal(1)
                    }
                },
                "result": TypeError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="validate_user_vars: " + data["case"]):
                with self.assertRaises(data["result"]):
                    validate_user_vars(**data["params"])


if __name__ == "__main__":
    unittest.main()
