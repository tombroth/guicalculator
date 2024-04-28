"""test_strtodecimal.py - Test script for the strtodecimal function."""

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

from guicalculator.calculator import strtodecimal


class StrToDecimalTest(unittest.TestCase):

    def test_strtodecimal(self):
        """Tests the strtodecimal function."""

        test_data = [
            {
                "case": "With commas",
                "params": {"val": "12,345.67800"},
                "result": Decimal("12345.678"),
            },
            {
                "case": "Without commas",
                "params": {"val": "12345.67800"},
                "result": Decimal("12345.678"),
            },
            {
                "case": "No input",
                "params": {"val": ""},
                "result": Decimal("0"),
            },
            {
                "case": "None input",
                "params": {"val": None},
                "result": Decimal("0"),
            },
        ]

        for data in test_data:
            with self.subTest(msg="strtodecimal: " + data["case"]):
                self.assertEqual(strtodecimal(**data["params"]), data["result"])

    def test_strtodecimal_invalid_input(self):
        """Tests the strtodecimal function with invalid input."""

        test_data = [
            {
                "case": "Invalid input",
                "params": {"val": "abc"},
                "result": InvalidOperation,
            },
        ]

        for data in test_data:
            with self.subTest(msg="strtodecimal: " + data["case"]):
                with self.assertRaises(data["result"]):
                    strtodecimal(**data["params"])


if __name__ == "__main__":
    unittest.main()
