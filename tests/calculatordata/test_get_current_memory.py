"""test_get_current_memory.py - Test script for the get_current_memory function."""

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

from guicalculator.calculator.calculatordata.private.getmem import get_current_memory
from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class GetCurrentMemoryTest(SetupCalculatorDataTest):

    def test_get_current_memory(self):
        """Test the get_current_memory function."""

        test_data = [
            {
                "case": "123",
                "current": {"mem": "123"},
                "ending": {"mem": "123"},
                "result": Decimal("123"),
            },
            {
                "case": "1,234.56",
                "current": {"mem": "1,234.56"},
                "ending": {"mem": "1,234.56"},
                "result": Decimal("1234.56"),
            },
            {
                "case": "Value not set",
                "current": {"mem": ""},
                "ending": {"mem": ""},
                "result": None,
            },
        ]

        for data in test_data:
            with self.subTest(msg="get_current_memory: " + data["case"]):
                res = self.run_basic_test(
                    func=get_current_memory,
                    cur_vals=data["current"],
                    params={"self": self.calc_data},
                    end_vals=data["ending"],
                )
                self.assertEqual(res, data["result"])

    def test_get_current_memory_invalid_input(self):
        """Test the get_current_memory function with invalid data."""

        test_data = [
            {
                "case": "Invalid value in mem",
                "current": {"mem": "abcdefg"},
                "result": InvalidOperation,
            },
            {
                "case": "Injection attack",
                "current": {"mem": lambda: __import__("os").system("dir")},
                "result": InvalidOperation,
            },
        ]

        for data in test_data:
            with self.subTest(msg="get_current_memory: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=get_current_memory,
                        cur_vals=data["current"],
                        params={"self": self.calc_data},
                    )


if __name__ == "__main__":
    unittest.main()
