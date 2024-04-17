import unittest
from decimal import Decimal

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
        """Tests the numtostr function."""

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


if __name__ == "__main__":
    unittest.main()
