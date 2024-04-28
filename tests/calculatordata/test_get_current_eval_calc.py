"""test_get_current_eval_calc.py - Test script for the get_current_eval_calc function."""

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

from guicalculator.globals import CalculatorFunctions
from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class GetCurrentEvalCalcTest(SetupCalculatorDataTest):

    def test_get_current_eval_calc(self):
        """Test the get_current_eval_calc function."""

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
                "result": "Decimal('123')",
            },
            {
                "case": "123 ** 2",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "params": {"symbol": "** 2"},
                "result": "Decimal('123') ** 2",
            },
            {
                "case": "sqrt(123)",
                "current": {"disp": "", "eval": "", "inpt": "123"},
                "params": {"func": CalculatorFunctions.SQUAREROOT},
                "result": "Decimal.sqrt(Decimal('123'))",
            },
            {
                "case": "Inversion: (1/3)",
                "current": {"disp": "", "eval": "", "inpt": "3"},
                "params": {"func": CalculatorFunctions.INVERSION},
                "result": "(1/Decimal('3'))",
            },
        ]

        for data in test_data:
            with self.subTest(msg="get_current_eval_calc: " + data["case"]):
                res = self.run_basic_test(
                    func=self.calc_data.get_current_eval_calc,
                    cur_vals=data["current"],
                    params=data["params"],
                    end_vals=data["current"],
                )
                self.assertEqual(res, data["result"])

    def test_get_current_eval_calc_invalid_input(self):
        """Test the get_current_eval_calc function with invalid input."""

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
                    "func": CalculatorFunctions.INVERSION,
                },
                "result": ValueError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="get_current_eval_calc: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.get_current_eval_calc,
                        cur_vals=data["current"],
                        params=data["params"],
                    )


if __name__ == "__main__":
    unittest.main()
