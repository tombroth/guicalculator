"""test_memory_store.py - Test script for the memory_store function."""

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

from guicalculator.calculator.calculatordata.private.memstore import memory_store
from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class MemoryStoreTest(SetupCalculatorDataTest):

    def test_memory_store(self):
        """Test the memory_store function."""

        test_data = [
            {
                "case": "No value in memory, value in input",
                "current": {"mem": "", "inpt": "321"},
                "ending": {"mem": "321", "inpt": "321"},
            },
            {
                "case": "No value in memory, no value in input",
                "current": {"mem": "", "inpt": ""},
                "ending": {"mem": "", "inpt": ""},
            },
            {
                "case": "Value in memory, no value in input",
                "current": {"mem": "123", "inpt": ""},
                "ending": {"mem": "123", "inpt": ""},
            },
            {
                "case": "321 overwrites 123",
                "current": {"mem": "123", "inpt": "321"},
                "ending": {"mem": "321", "inpt": "321"},
            },
            {
                "case": "1,234.56 overwrites 123",
                "current": {"mem": "123", "inpt": "1234.56"},
                "ending": {"mem": "1,234.56", "inpt": "1234.56"},
            },
        ]

        for data in test_data:
            with self.subTest(msg="memory_store: " + data["case"]):
                self.run_basic_test(
                    func=memory_store,
                    cur_vals=data["current"],
                    params={"self": self.calc_data},
                    end_vals=data["ending"],
                )

    def test_memory_store_invalid_input(self):
        """Test the memory_store function with invalid input."""

        test_data = [
            {
                "case": "Invalid value in input",
                "current": {"mem": "", "inpt": "abcdefg"},
                "result": InvalidOperation,
            },
            {
                "case": "Injection attack",
                "current": {
                    "mem": "",
                    "inpt": lambda: __import__("os").system("dir"),
                },
                "result": TypeError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="memory_store: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=memory_store,
                        cur_vals=data["current"],
                        params={"self": self.calc_data},
                        end_vals=data["current"],
                    )


if __name__ == "__main__":
    unittest.main()
