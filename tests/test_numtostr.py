"""test_numtostr.py - Test script for the numtostr function."""

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

from guicalculator.calculator import numtostr


class NumToStrTest(unittest.TestCase):

    def test_numtostr(self):
        """Tests the numtostr function."""

        test_data = [
            {
                "case": "int, default options (commas=False, removeZeroes=True)",
                "params": {"val": 12345},
                "result": "12345",
            },
            {
                "case": "int, commas=True",
                "params": {"val": 12345, "commas": True},
                "result": "12,345",
            },
            {
                "case": "int, removeZeroes=False",
                "params": {"val": 12345, "removeZeroes": False},
                "result": "12345",
            },
            {
                "case": "int, commas=True, removeZeroes=False",
                "params": {"val": 12345, "commas": True, "removeZeroes": False},
                "result": "12,345",
            },
            {
                "case": "float, default options (commas=False, removeZeroes=True)",
                "params": {"val": 12345.50},
                "result": "12345.5",
            },
            {
                "case": "float, commas=True",
                "params": {"val": 12345.50, "commas": True},
                "result": "12,345.5",
            },
            {
                "case": "float, removeZeroes=False",
                "params": {"val": 12345.50, "removeZeroes": False},
                "result": "12345.5",
            },
            {
                "case": "float, commas=True, removeZeroes=False",
                "params": {"val": 12345.50, "commas": True, "removeZeroes": False},
                "result": "12,345.5",
            },
            {
                "case": "Decimal, default options (commas=False, removeZeroes=True)",
                "params": {"val": Decimal("12345.50")},
                "result": "12345.5",
            },
            {
                "case": "Decimal, commas=True",
                "params": {"val": Decimal("12345.50"), "commas": True},
                "result": "12,345.5",
            },
            {
                "case": "Decimal, removeZeroes=False",
                "params": {"val": Decimal("12345.50"), "removeZeroes": False},
                "result": "12345.50",
            },
            {
                "case": "Decimal, commas=True, removeZeroes=False",
                "params": {
                    "val": Decimal("12345.50"),
                    "commas": True,
                    "removeZeroes": False,
                },
                "result": "12,345.50",
            },
        ]

        for data in test_data:
            with self.subTest(msg="numtostr: " + data["case"]):
                self.assertEqual(numtostr(**data["params"]), data["result"])

    def test_numtostr_invalid_input(self):
        """Tests the numtostr function with invalid input."""

        test_data = [
            {
                "case": "Invalid input",
                "params": {"val": "abc"},
                "result": ValueError,
            },
            {
                "case": "Empty input",
                "params": {"val": ""},
                "result": ValueError,
            },
            {
                "case": "None input",
                "params": {"val": None},
                "result": TypeError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="numtostr: " + data["case"]):
                with self.assertRaises(data["result"]):
                    numtostr(**data["params"])


if __name__ == "__main__":
    unittest.main()
