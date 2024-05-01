"""test_update_current_calc.py - Test script for the update_current_calc function."""

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

from guicalculator.globals import PI, CalculatorFunctions
from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class UpdateCurrentCalcTest(SetupCalculatorDataTest):

    def test_update_current_calc(self):
        """Test the update_current_calc function."""

        """
        We have already validated (in test_validate_symbol_and_func) that all 
        the valid symbols and functions should be accepted, so this test just 
        checks that basic functionality is working.
        """
        test_data = [
            {
                "case": "No parameters",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "params": {},
                "ending": {"disp": "123", "eval": "Decimal('123')", "inpt": ""},
            },
            {
                "case": "123 **",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "params": {"symbol": "**"},
                "ending": {
                    "disp": "123 **",
                    "eval": "Decimal('123') **",
                    "inpt": "",
                },
            },
            {
                "case": "sqrt(123)",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "params": {"func": CalculatorFunctions.SQUAREROOT},
                "ending": {
                    "disp": "sqrt(123)",
                    "eval": "Decimal.sqrt(Decimal('123'))",
                    "inpt": "",
                },
            },
            {
                "case": "Default variable e",
                "current": {"disp": "", "eval": "", "inpt": ""},
                "params": {"symbol": "e"},
                "ending": {"disp": "e", "eval": "e", "inpt": ""},
            },
            {
                "case": "Default variable PI",
                "current": {"disp": "", "eval": "", "inpt": ""},
                "params": {"symbol": PI},
                "ending": {"disp": PI, "eval": PI, "inpt": ""},
            },
            {
                "case": "User variable x",
                "current": {
                    "disp": "",
                    "eval": "",
                    "inpt": "",
                    "vars": {"x": Decimal("1234.56")},
                },
                "params": {"symbol": "x"},
                "ending": {"disp": "x", "eval": "x", "inpt": ""},
            },
        ]

        for data in test_data:
            with self.subTest(msg="update_current_calc: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.update_current_calc,
                    cur_vals=data["current"],
                    params=data["params"],
                    end_vals=data["ending"],
                )

    def test_update_current_calc_invalid_input(self):
        """Test the update_current_calc function with invlaid input"""

        """
        We have already validated (test_validate_symbol_and_func_invalid_input) 
        that all the invalid symbols and functions should be caught, so this test 
        just checks that basic functionality is working.
        """
        test_data = [
            {
                "case": "Both symbol and func specified",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "params": {
                    "symbol": "+",
                    "func": CalculatorFunctions.SQUAREROOT,
                },
                "result": ValueError,
            },
            {
                "case": "Unknown symbol",
                "current": {"disp": "", "eval": "", "inpt": "123", "vars": {}},
                "params": {
                    "symbol": "abcde",
                },
                "result": ValueError,
            },
            {
                "case": "Keyword",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "params": {
                    "symbol": "def",
                },
                "result": ValueError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="update_current_calc: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.update_current_calc,
                        cur_vals=data["current"],
                        params=data["params"],
                    )


if __name__ == "__main__":
    unittest.main()
