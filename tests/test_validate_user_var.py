import unittest
from decimal import Decimal

from guicalculator.calculator import validate_user_var


class ValidateUserVarTest(unittest.TestCase):

    def test_validate_user_var(self):
        """Tests the validate_user_var function."""

        test_data = [
            {
                "case": "Variable > 0",
                "params": {"nam": "x", "val": Decimal("1234.56")},
            },
            {
                "case": "Variable = 0",
                "params": {"nam": "x", "val": Decimal("0")},
            },
            {
                "case": "Variable < 0",
                "params": {"nam": "x", "val": Decimal("-1234.56")},
            },
        ]

        for data in test_data:
            with self.subTest(msg="validate_user_var: " + data["case"]):
                validate_user_var(**data["params"])

    def test_validate_user_var_invalid_input(self):
        """Tests the validate_user_var function with invalid input."""

        test_data = [
            {
                "case": "No data input",
                "params": {"nam": None, "val": None},
                "result": TypeError,
            },
            {
                "case": "Variable name not str",
                "params": {"nam": 123, "val": None},
                "result": TypeError,
            },
            {
                "case": "Invalid identifier",
                "params": {"nam": "x-y", "val": None},
                "result": TypeError,
            },
            {
                "case": "Reserved word",
                "params": {"nam": "def", "val": None},
                "result": TypeError,
            },
            {
                "case": "Replace default variable",
                "params": {"nam": "e", "val": None},
                "result": TypeError,
            },
            {
                "case": "Replace default variable",
                "params": {"nam": "e", "val": None},
                "result": TypeError,
            },
            {
                "case": "Valid name, no value",
                "params": {"nam": "x", "val": None},
                "result": TypeError,
            },
            {
                "case": "Valid name, non-Decimal value",
                "params": {"nam": "x", "val": 123.45},
                "result": TypeError,
            },
            {
                "case": "Injection attack 1",
                "params": {"nam": "x", "val": "__import__('os').system('dir')"},
                "result": TypeError,
            },
            {
                "case": "Injection attack 2",
                "params": {"nam": "x", "val": lambda: __import__("os").system("dir")},
                "result": TypeError,
            },
            {
                "case": "Injection attack 3",
                "params": {"nam": "__import__('os').system('dir')", "val": Decimal(1)},
                "result": TypeError,
            },
            {
                "case": "Injection attack 4",
                "params": {"nam": lambda: __import__("os").system("dir")},
                "val": Decimal(1),
                "result": TypeError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="validate_user_var: " + data["case"]):
                with self.assertRaises(data["result"]):
                    validate_user_var(**data["params"])


if __name__ == "__main__":
    unittest.main()
