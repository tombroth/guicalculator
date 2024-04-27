import unittest

from guicalculator.globals import CalculatorFunctions
from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class ValidateSymbolAndFuncTest(SetupCalculatorDataTest):

    def test_validate_symbol_and_func(self):
        """Test the validate_symbol_and_func function."""

        test_data = [
            {
                "case": "Both parameters empty",
                "params": {
                    "symbol": "",
                    "func": CalculatorFunctions.NOFUNCTION,
                },
            },
            {
                "case": "(",
                "params": {
                    "symbol": "(",
                    "func": CalculatorFunctions.NOFUNCTION,
                },
            },
            {
                "case": ")",
                "params": {
                    "symbol": ")",
                    "func": CalculatorFunctions.NOFUNCTION,
                },
            },
            {
                "case": "/",
                "params": {
                    "symbol": "/",
                    "func": CalculatorFunctions.NOFUNCTION,
                },
            },
            {
                "case": "*",
                "params": {
                    "symbol": "*",
                    "func": CalculatorFunctions.NOFUNCTION,
                },
            },
            {
                "case": "-",
                "params": {
                    "symbol": "-",
                    "func": CalculatorFunctions.NOFUNCTION,
                },
            },
            {
                "case": "+",
                "params": {
                    "symbol": "+",
                    "func": CalculatorFunctions.NOFUNCTION,
                },
            },
            {
                "case": "** 2",
                "params": {
                    "symbol": "** 2",
                    "func": CalculatorFunctions.NOFUNCTION,
                },
            },
            {
                "case": "**",
                "params": {
                    "symbol": "**",
                    "func": CalculatorFunctions.NOFUNCTION,
                },
            },
            {
                "case": "1/",
                "params": {
                    "symbol": "",
                    "func": CalculatorFunctions.INVERSION,
                },
            },
            {
                "case": "sqrt",
                "params": {
                    "symbol": "",
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
                    "symbol": "+",
                    "func": CalculatorFunctions.INVERSION,
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
                    "symbol": "",
                    "func": ("1/", "1/", "1/"),
                },
                "result": ValueError,
            },
            {
                "case": "Only one element in func tuple",  # test from when func was a tuple[str, str]
                "params": {
                    "symbol": "",
                    "func": ("1/"),
                },
                "result": ValueError,
            },
            {
                "case": "Elements in func tuple not str",  # test from when func was a tuple[str, str]
                "params": {
                    "symbol": "",
                    "func": (1, 1),
                },
                "result": ValueError,
            },
            {
                "case": "Invalid func tuple #1",  # test from when func was a tuple[str, str]
                "params": {
                    "symbol": "",
                    "func": ("1/", "sqrt"),
                },
                "result": ValueError,
            },
            {
                "case": "Invalid func tuple #2",  # test from when func was a tuple[str, str]
                "params": {
                    "symbol": "",
                    "func": ("print", "print"),
                },
                "result": ValueError,
            },
            {
                "case": "Func not a CalculatorFunctions",
                "params": {
                    "symbol": "",
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
