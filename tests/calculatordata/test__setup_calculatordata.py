import unittest
from tkinter import Tk
from typing import Any, Callable
from unittest.mock import MagicMock

from guicalculator.calculator import CalculatorData


class SetupCalculatorDataTest(unittest.TestCase):
    root = Tk()  # needed to instantiate the StringVar

    # functions to mock
    update_display = MagicMock()
    clear_display = MagicMock()
    write_to_display = MagicMock()
    bell = MagicMock()
    vars_popup = MagicMock()

    calc_data = CalculatorData(
        update_display,
        clear_display,
        write_to_display,
        bell,
        vars_popup,
    )

    def set_current_disp_eval_inpt(self, cur_vals: dict) -> None:
        """
        set_current_display_eval_input - Sets the variables in calc_data.

        The keys used from cur_vals are:

        * "disp" - current_display_calc
        * "eval" - current_eval_calc
        * "inpt" - current_input
        * "mem" - memval - the value stored in memory
        * "vars" - user_variables

        Parameters
        ----------
        cur_vals : dict
            A dictionary with the values for the variables
        """

        if "disp" in cur_vals:
            self.calc_data._current_display_calc = cur_vals["disp"]
        if "eval" in cur_vals:
            self.calc_data._current_eval_calc = cur_vals["eval"]
        if "inpt" in cur_vals:
            self.calc_data._current_input = cur_vals["inpt"]
        if "mem" in cur_vals:
            self.calc_data._memval.set(cur_vals["mem"])
        if "vars" in cur_vals:
            self.calc_data._user_variables = cur_vals["vars"]

    def chk_current_disp_eval_inpt(self, cur_vals: dict) -> None:
        """
        chk_current_disp_eval_inpt - Asserts the values of the variables
        in calc_data are what they should be.

        The keys used from cur_vals are:

        * "disp" - current_display_calc
        * "eval" - current_eval_calc
        * "inpt" - current_input
        * "mem" - memval - the value stored in memory
        * "vars" - user_variables

        Parameters
        ----------
        cur_vals : dict
            A dictionary with the values to check the variables against
        """

        if "disp" in cur_vals:
            self.assertEqual(
                self.calc_data._current_display_calc,
                cur_vals["disp"],
                "current_display_calc",
            )
        if "eval" in cur_vals:
            self.assertEqual(
                self.calc_data._current_eval_calc,
                cur_vals["eval"],
                "current_eval_calc",
            )
        if "inpt" in cur_vals:
            self.assertEqual(
                self.calc_data._current_input,
                cur_vals["inpt"],
                "current_input",
            )
        if "mem" in cur_vals:
            self.assertEqual(
                self.calc_data._memval.get(),
                cur_vals["mem"],
                "memval",
            )
        if "vars" in cur_vals:
            self.assertEqual(
                self.calc_data._user_variables,
                cur_vals["vars"],
                "user_variables",
            )

    def run_basic_test(
        self, func: Callable, cur_vals: dict, params: dict = {}, end_vals: dict = {}
    ) -> Any:
        """
        run_basic_test - Runs a basic test that

        1. Sets the current_display_calc, current_eval_calc, and current_input
        variables to the values in cur_vals.
        2. Executes the function, passing any parameters from params.
        3. Checks the values in current_display_calc, current_eval_calc, and
        current_input variables against end_vals.
        4. Returns any result from the function.


        Parameters
        ----------
        func : Callable
            The function to execute
        cur_vals : dict
            Current values passed to set_current_disp_eval_inpt function
        params : dict, optional
            Function parameters passed as **params, by default {}
        end_vals : dict, optional
            Ending values passed to chk_current_disp_eval_inpt function, by default {}

        Returns
        -------
        Any
            return value from function
        """

        self.set_current_disp_eval_inpt(cur_vals)
        res = func(**params)
        if end_vals:
            self.chk_current_disp_eval_inpt(end_vals)
        return res


if __name__ == "__main__":
    unittest.main()
