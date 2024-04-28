"""test_get_current_input.py - Test script for the get_current_input function."""

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
from decimal import Decimal, InvalidOperation

from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class GetCurrentInputTest(SetupCalculatorDataTest):

    def test_get_current_input(self):
        """Test the get_current_input function."""

        test_data = [
            {
                "case": "123 as str",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "result": Decimal("123"),
            },
            {
                "case": "123 as int",
                "current": {"disp": "", "eval": "", "inpt": 123},
                "result": Decimal("123"),
            },
            {
                "case": "No input value",
                "current": {"disp": "", "eval": "", "inpt": ""},
                "result": Decimal("0"),
            },
        ]

        for data in test_data:
            with self.subTest(msg="get_current_input: " + data["case"]):
                res = self.run_basic_test(
                    func=self.calc_data.get_current_input,
                    cur_vals=data["current"],
                    end_vals=data["current"],
                )
                self.assertEqual(res, data["result"])

    def test_get_current_input_invalid_input(self):
        """Test the get_current_input function with invalid input."""

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
            with self.subTest(msg="get_current_input: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.get_current_input,
                        cur_vals=data["current"],
                    )


if __name__ == "__main__":
    unittest.main()
