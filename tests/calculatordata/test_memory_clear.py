import unittest

from tests.calculatordata.test__setup_calculatordata import SetupCalculatorDataTest


class MemoryClearTest(SetupCalculatorDataTest):

    def test_memory_clear(self):
        """Test the memory_clear function"""

        test_data = [
            {
                "case": "No value in memory",
                "current": {"mem": ""},
                "ending": {"mem": ""},
            },
            {
                "case": "123",
                "current": {"mem": "123"},
                "ending": {"mem": ""},
            },
            {
                "case": "1,234.56",
                "current": {"mem": "1,234.56"},
                "ending": {"mem": ""},
            },
        ]

        for data in test_data:
            with self.subTest(msg="memory_clear: " + data["case"]):
                self.run_basic_test(
                    func=self.calc_data.memory_clear,
                    cur_vals=data["current"],
                    end_vals=data["ending"],
                )

    # memory_clear doesn't take input, so there isn't an invalid input check


if __name__ == "__main__":
    unittest.main()
