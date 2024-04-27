import unittest
from decimal import Decimal, InvalidOperation

from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class GetCurrentMemoryTest(SetupCalculatorDataTest):

    def test_get_current_memory(self):
        """Test the get_current_memory function."""

        test_data = [
            {
                "case": "123",
                "current": {"mem": "123"},
                "ending": {"mem": "123"},
                "result": Decimal("123"),
            },
            {
                "case": "1,234.56",
                "current": {"mem": "1,234.56"},
                "ending": {"mem": "1,234.56"},
                "result": Decimal("1234.56"),
            },
            {
                "case": "Value not set",
                "current": {"mem": ""},
                "ending": {"mem": ""},
                "result": Decimal("0"),
            },
        ]

        for data in test_data:
            with self.subTest(msg="get_current_memory: " + data["case"]):
                res = self.run_basic_test(
                    func=self.calc_data.get_current_memory,
                    cur_vals=data["current"],
                    end_vals=data["ending"],
                )
                self.assertEqual(res, data["result"])

    def test_get_current_memory_invalid_input(self):
        """Test the get_current_memory function with invalid data."""

        test_data = [
            {
                "case": "Invalid value in mem",
                "current": {"mem": "abcdefg"},
                "result": InvalidOperation,
            },
            {
                "case": "Injection attack",
                "current": {"mem": lambda: __import__("os").system("dir")},
                "result": InvalidOperation,
            },
        ]

        for data in test_data:
            with self.subTest(msg="get_current_memory: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.get_current_memory,
                        cur_vals=data["current"],
                    )


if __name__ == "__main__":
    unittest.main()
