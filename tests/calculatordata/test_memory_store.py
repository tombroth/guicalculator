from decimal import InvalidOperation
import unittest

from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class MemoryStoreTest(SetupCalculatorDataTest):

    def test_memory_store(self):
        """Test the memory_store function."""

        test_data = [
            {
                "case": "No value in memory, value in input",
                "current": {"mem": "", "inpt": "321"},
                "ending": {"mem": "321", "inpt": "321"},
            },
            {
                "case": "No value in memory, no value in input",
                "current": {"mem": "", "inpt": ""},
                "ending": {"mem": "0", "inpt": "0"},
            },
            {
                "case": "Value in memory, no value in input",
                "current": {"mem": "123", "inpt": ""},
                "ending": {"mem": "0", "inpt": "0"},
            },
            {
                "case": "321 overwrites 123",
                "current": {"mem": "123", "inpt": "321"},
                "ending": {"mem": "321", "inpt": "321"},
            },
            {
                "case": "1,234.56 overwrites 123",
                "current": {"mem": "123", "inpt": "1234.56"},
                "ending": {"mem": "1,234.56", "inpt": "1234.56"},
            },
        ]

        for data in test_data:
            with self.subTest(msg="memory_store: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.memory_store,
                    cur_vals=data["current"],
                    end_vals=data["ending"],
                )

    def test_memory_store_invalid_input(self):
        """Test the memory_store function with invalid input."""

        test_data = [
            {
                "case": "Invalid value in input",
                "current": {"mem": "", "inpt": "abcdefg"},
                "result": InvalidOperation,
            },
            {
                "case": "Injection attack",
                "current": {
                    "mem": "",
                    "inpt": lambda: __import__("os").system("dir"),
                },
                "result": TypeError,
            },
        ]

        for data in test_data:
            with self.subTest(msg="memory_store: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.memory_store,
                        cur_vals=data["current"],
                    )


if __name__ == "__main__":
    unittest.main()
