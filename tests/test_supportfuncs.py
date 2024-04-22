import unittest
from decimal import Decimal, DivisionByZero, InvalidOperation

from guicalculator import supportfuncs as sf  # type: ignore


class SupportFuncsTest(unittest.TestCase):

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
                self.assertEqual(sf.numtostr(**data["params"]), data["result"])

    def test_numtostr_invalid_input(self):
        """Tests the numtostr function with invalid input."""

        test_data = [
            {
                "case": "Invalid input",
                "params": {"val": "abc"},
                "result": ValueError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="numtostr: " + data["case"]):
                with self.assertRaises(data["result"]):
                    sf.numtostr(**data["params"])

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
        ]

        for data in test_data:
            with self.subTest(msg="strtodecimal: " + data["case"]):
                self.assertEqual(sf.strtodecimal(**data["params"]), data["result"])

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
                    sf.strtodecimal(**data["params"])

    def test_evaluate_calculation(self):
        """Tests the evaluate_calculation function."""

        test_data = [
            {
                "params": {
                    "current_calculation": "1 + 1",
                    "user_variables": {},
                },
                "result": Decimal("2"),
            },
            {
                "params": {
                    "current_calculation": "0.3 - 0.2",
                    "user_variables": {},
                },
                "result": Decimal("0.0999999999999999777955395074"),
            },
            {
                "params": {
                    "current_calculation": "Decimal('0.3') - Decimal('0.2')",
                    "user_variables": {},
                },
                "result": Decimal("0.1"),
            },
            {
                "params": {
                    "current_calculation": "decimal.Decimal('0.3') + decimal.Decimal('2')",
                    "user_variables": {},
                },
                "result": Decimal("2.3"),
            },
            {
                "params": {
                    "current_calculation": "Decimal('3') * Decimal('2')",
                    "user_variables": {},
                },
                "result": Decimal("6"),
            },
            {
                "params": {
                    "current_calculation": "Decimal('6') / Decimal('2')",
                    "user_variables": {},
                },
                "result": Decimal("3"),
            },
            {
                "params": {
                    "current_calculation": "- Decimal('2')",
                    "user_variables": {},
                },
                "result": Decimal("-2"),
            },
            {
                "params": {
                    "current_calculation": "+ Decimal('2')",
                    "user_variables": {},
                },
                "result": Decimal("2"),
            },
            {
                "params": {
                    "current_calculation": "Decimal('9') / ( Decimal('1') + Decimal('2') )",
                    "user_variables": {},
                },
                "result": Decimal("3"),
            },
            {
                "params": {
                    "current_calculation": "e",
                    "user_variables": {},
                },
                "result": Decimal("2.718281828459045235360287471"),
            },
            {
                "params": {
                    "current_calculation": "\u03c0",  # greek letter pi
                    "user_variables": {},
                },
                "result": Decimal("3.141592653589793238462643383"),
            },
            {
                "params": {
                    "current_calculation": "abc + defg",
                    "user_variables": {
                        "abc": Decimal("123"),
                        "defg": Decimal("456"),
                    },
                },
                "result": Decimal("579"),
            },
        ]

        for data in test_data:
            with self.subTest(
                msg="evaluate_calculation: " + data["params"]["current_calculation"]
            ):
                self.assertEqual(
                    sf.evaluate_calculation(**data["params"]), data["result"]
                )

    def test_evaluate_calculation_invalid_input(self):
        """Tests the evaluate_calculation function with invalid input."""

        test_data = [
            {
                "case": "Decimal with no parameter",
                "params": {
                    "current_calculation": "Decimal()",
                    "user_variables": {},
                },
                "result": TypeError,
            },
            {
                "case": "Decimal with two parameters",
                "params": {
                    "current_calculation": "Decimal(1,2)",
                    "user_variables": {},
                },
                "result": TypeError,
            },
            {
                "case": "Decimal with non-str parameter",
                "params": {
                    "current_calculation": "Decimal(1)",
                    "user_variables": {},
                },
                "result": TypeError,
            },
            {
                "case": "Divide by zero",
                "params": {
                    "current_calculation": "1 / 0",
                    "user_variables": {},
                },
                "result": DivisionByZero,
            },
            {
                "case": "Missing parenthesis",
                "params": {
                    "current_calculation": "10 / ( 2 ",
                    "user_variables": {},
                },
                "result": SyntaxError,
            },
            {
                "case": "Undefined variable",
                "params": {
                    "current_calculation": "abc",
                    "user_variables": {},
                },
                "result": TypeError,
            },
            {
                "case": "Invalid variable - not an identifier",
                "params": {
                    "current_calculation": "a-b",
                    "user_variables": {"a-b": Decimal(2)},
                },
                "result": TypeError,
            },
            {
                "case": "Invalid variable - keyword",
                "params": {
                    "current_calculation": "def",
                    "user_variables": {"def": Decimal(2)},
                },
                "result": TypeError,
            },
            {
                "case": "Invalid variable - attempt to replace default variable",
                "params": {
                    "current_calculation": "e",
                    "user_variables": {"e": Decimal(2)},
                },
                "result": TypeError,
            },
            {
                "case": "Invalid variable - not str",
                "params": {
                    "current_calculation": "e",
                    "user_variables": {123: Decimal(2)},
                },
                "result": TypeError,
            },
            {
                "case": "Invalid variable - None name",
                "params": {
                    "current_calculation": "e",
                    "user_variables": {None: Decimal(2)},
                },
                "result": TypeError,
            },
            {
                "case": "Invalid variable - not Decimal value",
                "params": {
                    "current_calculation": "a",
                    "user_variables": {"a": 2},
                },
                "result": TypeError,
            },
            {
                "case": "Invalid variable - None value",
                "params": {
                    "current_calculation": "a",
                    "user_variables": {"a": None},
                },
                "result": TypeError,
            },
            {
                "case": "Called function other than Decimal",
                "params": {
                    "current_calculation": "print(123)",
                    "user_variables": {},
                },
                "result": TypeError,
            },
            {
                "case": "Formatted string",
                "params": {
                    "current_calculation": "f'{3.1415:.2}'",
                    "user_variables": {},
                },
                "result": TypeError,
            },
            {
                "case": "List",
                "params": {
                    "current_calculation": "[1, 2, 3]",
                    "user_variables": {},
                },
                "result": TypeError,
            },
            {
                "case": "Tuple",
                "params": {
                    "current_calculation": "(1, 2, 3)",
                    "user_variables": {},
                },
                "result": TypeError,
            },
            {
                "case": "Set",
                "params": {
                    "current_calculation": "{1, 2, 3}",
                    "user_variables": {},
                },
                "result": TypeError,
            },
            {
                "case": "Dict",
                "params": {
                    "current_calculation": "{'a': 123}",
                    "user_variables": {},
                },
                "result": TypeError,
            },
            {
                "case": "Str",
                "params": {
                    "current_calculation": "'a'",
                    "user_variables": {},
                },
                "result": TypeError,
            },
            {
                "case": "Assignment",
                "params": {
                    "current_calculation": "a = 1",
                    "user_variables": {},
                },
                "result": SyntaxError,
            },
            {
                "case": "Comparison, less than",
                "params": {
                    "current_calculation": "a < 1",
                    "user_variables": {},
                },
                "result": TypeError,
            },
            {
                "case": "Binary operator **",
                "params": {
                    "current_calculation": "2 ** 3",
                    "user_variables": {},
                },
                "result": KeyError,
            },
            {
                "case": "Unary operator bitwise inversion",
                "params": {
                    "current_calculation": "~7",
                    "user_variables": {},
                },
                "result": KeyError,
            },
            {
                "case": "Star operator *a",
                "params": {
                    "current_calculation": "*args",
                    "user_variables": {},
                },
                "result": SyntaxError,
            },
            {
                "case": "Logical or",
                "params": {
                    "current_calculation": "1 or 2",
                    "user_variables": {},
                },
                "result": TypeError,
            },
            {
                "case": "If expression",
                "params": {
                    "current_calculation": "a if b else c",
                    "user_variables": {"a": 1, "b": 0, "c": 2},
                },
                "result": TypeError,
            },
            {
                "case": "Injection attack 1",
                "params": {
                    "current_calculation": "__import__('os').system('dir')",
                    "user_variables": {},
                },
                "result": TypeError,
            },
            {
                "case": "Injection attack 2",
                "params": {
                    "current_calculation": lambda: __import__("os").system("dir"),
                    "user_variables": {},
                },
                "result": TypeError,
            },
            {
                "case": "Empty calculation",
                "params": {
                    "current_calculation": None,
                    "user_variables": {},
                },
                "result": TypeError,
            },
            {
                "case": "Calculation not a str",
                "params": {
                    "current_calculation": (1, 2, 3),
                    "user_variables": {},
                },
                "result": TypeError,
            },
            {
                "case": "Augmented assignment, a += 1",
                "params": {
                    "current_calculation": "a += 1",
                    "user_variables": {},
                },
                "result": SyntaxError,
            },
            {
                "case": "Injection by user variable 1",
                "params": {
                    "current_calculation": "a",
                    "user_variables": {"a": "__import__('os').system('dir')"},
                },
                "result": TypeError,
            },
            {
                "case": "Injection by user variable 2",
                "params": {
                    "current_calculation": "a",
                    "user_variables": {
                        "a": lambda: __import__("os").system("dir"),
                    },
                },
                "result": TypeError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="evaluate_calculation: " + data["case"]):
                with self.assertRaises(data["result"]):
                    sf.evaluate_calculation(**data["params"])


if __name__ == "__main__":
    unittest.main()
