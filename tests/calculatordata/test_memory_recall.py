"""test_memory_recall.py - Test script for the memory_recall function."""

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

from guicalculator.calculator.calculatordata.private.memrecall import memory_recall
from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class MemoryRecallTest(SetupCalculatorDataTest):

    def test_memory_recall(self):
        """Test the memory_recall function."""

        test_data = [
            {
                "case": "No value in memory",
                "current": {"mem": "", "inpt": "321"},
                "ending": {"mem": "", "inpt": "321"},
            },
            {
                "case": "123",
                "current": {"mem": "123", "inpt": "321"},
                "ending": {"mem": "123", "inpt": "123"},
            },
            {
                "case": "1,234.56",
                "current": {"mem": "1,234.56", "inpt": "321"},
                "ending": {"mem": "1,234.56", "inpt": "1234.56"},
            },
        ]

        for data in test_data:
            with self.subTest(msg="memory_recall: " + data["case"]):
                self.run_basic_test(
                    func=memory_recall,
                    cur_vals=data["current"],
                    params={"self": self.calc_data},
                    end_vals=data["ending"],
                )

    def test_memory_recall_invalid_input(self):
        """Test the memory_recall function with invalid input."""

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
            with self.subTest(msg="memory_recall: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=memory_recall,
                        cur_vals=data["current"],
                        params={"self": self.calc_data},
                        end_vals=data["current"],
                    )


if __name__ == "__main__":
    unittest.main()
