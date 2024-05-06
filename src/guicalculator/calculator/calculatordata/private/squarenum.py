from ....globals import CalculatorFunctions
from ...logwrapper import logerror, object_wrapper
from ..calculatordata import CalculatorData
from .updatecalc import update_current_calc


@object_wrapper
def square_number(self: CalculatorData) -> None:
    """
    square_number - Convert the current number being input to its
    square: x**2.

    Notes
    -----
    As a side effect, will round the number currently being input to the
    precision in the Decimal context.
    """

    try:
        update_current_calc(self, func=CalculatorFunctions.SQUARE)
    except Exception as e:
        logerror(e, "square_number", 2)
        self.bell()
