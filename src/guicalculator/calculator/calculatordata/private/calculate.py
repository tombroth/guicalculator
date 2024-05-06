from ...evaluate_calculation import evaluate_calculation
from ...logwrapper import logerror, object_wrapper
from ...numtostr import numtostr
from ..calculatordata import CalculatorData
from ..functions.evalcalc import get_current_eval_calc
from .updatecalc import update_current_calc


@object_wrapper
def calculate(self: CalculatorData) -> None:
    """
    calculate - Performs the current calculation and updates the display
    with the results.
    """

    # update current calc and display
    update_current_calc(self)

    cur_calc = get_current_eval_calc(self)

    # if we have a calculation to perform
    if cur_calc:
        try:
            # run the current calculation
            val = evaluate_calculation(
                cur_calc,
                self._user_variables,
            )

            # show the result
            self.write_to_display(f" = {numtostr(val, commas=True)}\n{'=' * 30}\n")

            # clear current calc and set current input to result
            self._current_calc = []
            self._current_input = numtostr(val) or ""

        except Exception as e:
            logerror(e, "calculate", 2)

            # clear the current calculation and display the error message
            errmsg = e.__class__.__qualname__
            if errmsg == "TypeError":
                errmsg = str(e).split(":")[0]
            elif errmsg == "SyntaxError":
                errmsg = f"{errmsg}: {str(e)}"
                unknown_line_1 = " (<unknown>, line 1)"
                if errmsg.endswith(unknown_line_1):
                    errmsg = errmsg[: -(len(unknown_line_1))]
            self.write_to_display(f"=== ERROR ===\n{errmsg}\n=== ERROR ===\n")

            self._current_calc = []
            self._current_input = ""

    # update the display
    self.update_display()
