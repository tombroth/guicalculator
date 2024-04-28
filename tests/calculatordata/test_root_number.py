"""test_root_number.py - Test script for the root_number function."""

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
from decimal import InvalidOperation

from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class RootNumberTest(SetupCalculatorDataTest):

    def test_root_number(self):
        """Test the root_number function."""

        test_data = [
            {
                "case": "2 as str",
                "current": {"disp": "", "eval": "", "inpt": "2"},
                "ending": {
                    "disp": "sqrt(2)",
                    "eval": "Decimal.sqrt(Decimal('2'))",
                    "inpt": "",
                },
            },
            {
                "case": "2 as int",
                "current": {"disp": "", "eval": "", "inpt": 2},
                "ending": {
                    "disp": "sqrt(2)",
                    "eval": "Decimal.sqrt(Decimal('2'))",
                    "inpt": "",
                },
            },
            {
                "case": "No input value",
                "current": {"disp": "", "eval": "", "inpt": ""},
                "ending": {"disp": "", "eval": "", "inpt": ""},
            },
        ]

        for data in test_data:
            with self.subTest(msg="root_number: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.root_number,
                    cur_vals=data["current"],
                    end_vals=data["ending"],
                )

    def test_root_number_invalid_input(self):
        """Test the root_number function with invalid input."""

        test_data = [
            {
                "case": "Text stored in input",
                "current": {"disp": "", "eval": "", "inpt": "abcdefg"},
                "result": InvalidOperation,
            },
            {
                "case": "List stored in input",
                "current": {"disp": "", "eval": "", "inpt": ["1", "2", "3"]},
                "result": ValueError,
            },
            {
                "case": "Injection attack #1",
                "current": {
                    "disp": "",
                    "eval": "",
                    "inpt": "__import__('os').system('dir')",
                },
                "result": InvalidOperation,
            },
            {
                "case": "Injection attack #2",
                "current": {
                    "disp": "",
                    "eval": "",
                    "inpt": lambda: __import__("os").system("dir"),
                },
                "result": TypeError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="root_number: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.root_number,
                        cur_vals=data["current"],
                    )


if __name__ == "__main__":
    unittest.main()