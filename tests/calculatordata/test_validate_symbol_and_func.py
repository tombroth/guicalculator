"""test_validate_symbol_and_func.py - Test script for the validate_symbol_and_func function."""

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
from guicalculator.globals.enums import CalculatorSymbols
from guicalculator.globals.functionstype import FunctionsType
from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class ValidateSymbolAndFuncTest(SetupCalculatorDataTest):

    def test_validate_symbol_and_func(self):
        """Test the validate_symbol_and_func function."""

        test_data = [
            {
                "case": "Both parameters empty",
                "params": {
                    "symbol": CalculatorSymbols.NOSYMBOL,
                    "func": CalculatorFunctions.NOFUNCTION,
                },
            },
            {
                "case": "Both parameters empty #2",
                "params": {
                    "symbol": None,
                    "func": None,
                },
            },
            {
                "case": "(",
                "params": {
                    "symbol": CalculatorSymbols.OPENPAREN,
                    "func": CalculatorFunctions.NOFUNCTION,
                },
            },
            {
                "case": ")",
                "params": {
                    "symbol": CalculatorSymbols.CLOSEPAREN,
                    "func": CalculatorFunctions.NOFUNCTION,
                },
            },
            {
                "case": "/",
                "params": {
                    "symbol": CalculatorSymbols.DIVISION,
                    "func": CalculatorFunctions.NOFUNCTION,
                },
            },
            {
                "case": "*",
                "params": {
                    "symbol": CalculatorSymbols.MULTIPLICATION,
                    "func": CalculatorFunctions.NOFUNCTION,
                },
            },
            {
                "case": "-",
                "params": {
                    "symbol": CalculatorSymbols.SUBTRACTION,
                    "func": CalculatorFunctions.NOFUNCTION,
                },
            },
            {
                "case": "+",
                "params": {
                    "symbol": CalculatorSymbols.ADDITION,
                    "func": CalculatorFunctions.NOFUNCTION,
                },
            },
            {
                "case": "**",
                "params": {
                    "symbol": CalculatorSymbols.EXPONENTIATION,
                    "func": CalculatorFunctions.NOFUNCTION,
                },
            },
            {
                "case": "sqrt",
                "params": {
                    "symbol": CalculatorSymbols.NOSYMBOL,
                    "func": CalculatorFunctions.SQUAREROOT,
                },
            },
        ]

        for data in test_data:
            with self.subTest(msg="validate_symbol_and_func: " + data["case"]):
                self.calc_data.validate_symbol_and_func(**data["params"])

    def test_validate_symbol_and_func_invalid_input(self):
        """Test the validate_symbol_and_func function with invalid input."""

        test_data = [
            {
                "case": "Both parameters used",
                "params": {
                    "symbol": CalculatorSymbols.ADDITION,
                    "func": CalculatorFunctions.SQUAREROOT,
                },
                "result": ValueError,
            },
            {
                "case": "Symbol not a str",
                "params": {
                    "symbol": ["+", "-"],
                    "func": CalculatorFunctions.NOFUNCTION,
                },
                "result": ValueError,
            },
            {
                "case": "Symbol not valid",
                "params": {
                    "symbol": "+-*/",
                    "func": CalculatorFunctions.NOFUNCTION,
                },
                "result": ValueError,
            },
            {
                "case": "More than two elements in func tuple",  # test from when func was a tuple[str, str]
                "params": {
                    "symbol": CalculatorSymbols.NOSYMBOL,
                    "func": ("1/", "1/", "1/"),
                },
                "result": ValueError,
            },
            {
                "case": "Only one element in func tuple",  # test from when func was a tuple[str, str]
                "params": {
                    "symbol": CalculatorSymbols.NOSYMBOL,
                    "func": ("1/"),
                },
                "result": ValueError,
            },
            {
                "case": "Elements in function not str",
                "params": {
                    "symbol": CalculatorSymbols.NOSYMBOL,
                    "func": FunctionsType(1, 1),
                },
                "result": ValueError,
            },
            {
                "case": "Invalid function",
                "params": {
                    "symbol": CalculatorSymbols.NOSYMBOL,
                    "func": FunctionsType("1/", "sqrt"),
                },
                "result": ValueError,
            },
            {
                "case": "Invalid function #2",
                "params": {
                    "symbol": CalculatorSymbols.NOSYMBOL,
                    "func": FunctionsType("print", "print"),
                },
                "result": ValueError,
            },
            {
                "case": "Func not a FunctionsType",
                "params": {
                    "symbol": CalculatorSymbols.NOSYMBOL,
                    "func": 42,
                },
                "result": ValueError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="validate_symbol_and_func: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.calc_data.validate_symbol_and_func(**data["params"])


if __name__ == "__main__":
    unittest.main()
