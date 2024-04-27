import unittest
from decimal import Decimal, InvalidOperation

from guicalculator.calculator import strtodecimal


class StrToDecimalTest(unittest.TestCase):

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
            {
                "case": "None input",
                "params": {"val": None},
                "result": Decimal("0"),
            },
        ]

        for data in test_data:
            with self.subTest(msg="strtodecimal: " + data["case"]):
                self.assertEqual(strtodecimal(**data["params"]), data["result"])

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
                    strtodecimal(**data["params"])


if __name__ == "__main__":
    unittest.main()
