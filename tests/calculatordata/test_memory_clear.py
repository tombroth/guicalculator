"""test_memory_clear.py - Test script for the memory_clear function."""

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

from guicalculator.calculator.calculatordata.private.memclear import memory_clear
from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class MemoryClearTest(SetupCalculatorDataTest):

    def test_memory_clear(self):
        """Test the memory_clear function"""

        test_data = [
            {
                "case": "No value in memory",
                "current": {"mem": ""},
                "ending": {"mem": ""},
            },
            {
                "case": "123",
                "current": {"mem": "123"},
                "ending": {"mem": ""},
            },
            {
                "case": "1,234.56",
                "current": {"mem": "1,234.56"},
                "ending": {"mem": ""},
            },
        ]

        for data in test_data:
            with self.subTest(msg="memory_clear: " + data["case"]):
                self.run_basic_test(
                    func=memory_clear,
                    cur_vals=data["current"],
                    params={"self": self.calc_data},
                    end_vals=data["ending"],
                )

    # memory_clear doesn't take input, so there isn't an invalid input check


if __name__ == "__main__":
    unittest.main()
