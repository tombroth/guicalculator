import unittest
from decimal import InvalidOperation

from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class MemoryRecallTest(SetupCalculatorDataTest):

    def test_memory_recall(self):
        """Test the memory_recall function."""

        test_data = [
            {
                "case": "No value in memory",
                "current": {"mem": "", "inpt": "321"},
                "ending": {"mem": "", "inpt": "0"},
            },
            {
                "case": "123",
                "current": {"mem": "123", "inpt": "321"},
                "ending": {"mem": "123", "inpt": "123"},
            },
            {
                "case": "1,234.56",
                "current": {"mem": "1,234.56", "inpt": "321"},
                "ending": {"mem": "1,234.56", "inpt": "1234.56"},
            },
        ]

        for data in test_data:
            with self.subTest(msg="memory_recall: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.memory_recall,
                    cur_vals=data["current"],
                    end_vals=data["ending"],
                )

    def test_memory_recall_invalid_input(self):
        """Test the memory_recall function with invalid input."""

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
            with self.subTest(msg="memory_recall: " + data["case"]):
                with self.assertRaises(data["result"]):
                    self.run_basic_test(
                        func=self.calc_data.memory_recall,
                        cur_vals=data["current"],
                    )


if __name__ == "__main__":
    unittest.main()
