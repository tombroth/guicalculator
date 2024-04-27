import unittest
from decimal import InvalidOperation

from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class MemorySwapTest(SetupCalculatorDataTest):

    def test_memory_swap(self):
        """Test the memory_swap function."""

        test_data = [
            {
                "case": "No value in memory, value in input",
                "current": {"mem": "", "inpt": "321"},
                "ending": {"mem": "321", "inpt": "0"},
            },
            {
                "case": "No value in memory, no value in input",
                "current": {"mem": "", "inpt": ""},
                "ending": {"mem": "0", "inpt": "0"},
            },
            {
                "case": "Value in memory, no value in input",
                "current": {"mem": "123", "inpt": ""},
                "ending": {"mem": "0", "inpt": "123"},
            },
            {
                "case": "321 swaps with 123",
                "current": {"mem": "123", "inpt": "321"},
                "ending": {"mem": "321", "inpt": "123"},
            },
            {
                "case": "1,234.56 swaps with 123",
                "current": {"mem": "123", "inpt": "1234.56"},
                "ending": {"mem": "1,234.56", "inpt": "123"},
            },
        ]

        for data in test_data:
            with self.subTest(msg="memory_swap: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.memory_swap,
                    cur_vals=data["current"],
                    end_vals=data["ending"],
                )

    def test_memory_swap_invalid_input(self):
        """Test the memory_swap function with invalid input."""

        test_data = [
            {
                "case": "Invalid value in input",
                "current": {"mem": "", "inpt": "abcdefg"},
                "result": InvalidOperation,
            },
            {
                "case": "Injection attack in input",
                "current": {
                    "mem": "",
                    "inpt": lambda: __import__("os").system("dir"),
                },
                "result": TypeError,
            },
            {
                "case": "Invalid value in memory",
                "current": {"inpt": "", "mem": "abcdefg"},
                "result": InvalidOperation,
            },
            {
                "case": "Injection attack in memory",
                "current": {
                    "inpt": "",
                    "mem": lambda: __import__("os").system("dir"),
                },
                "result": InvalidOperation,
            },
        ]

        for data in test_data:
            with self.subTest(msg="memory_swap: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.memory_swap,
                        cur_vals=data["current"],
                    )


if __name__ == "__main__":
    unittest.main()
