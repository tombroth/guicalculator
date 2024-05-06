from ....globals import CalculatorFunctions
from ...logwrapper import logerror, object_wrapper
from ..calculatordata import CalculatorData
from .updatecalc import update_current_calc


@object_wrapper
def root_number(self: CalculatorData) -> None:
    """
    root_number - Convert the current number being input to its
    square root: Decimal.sqrt(x).

    Notes
    -----
    As a side effect, will round the number currently being input to the
    precision in the Decimal context.
    """

    try:
        update_current_calc(self, func=CalculatorFunctions.SQUAREROOT)
    except Exception as e:
        logerror(e, "root_number", 2)
        self.bell()
