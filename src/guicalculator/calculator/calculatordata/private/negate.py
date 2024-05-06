from ....globals import CalculatorFunctions
from ...logwrapper import logerror, object_wrapper
from ..calculatordata import CalculatorData
from .updatecalc import update_current_calc


@object_wrapper
def negate(self: CalculatorData) -> None:
    """
    invert_sign - Convert the current number being input from positive to
    negative or negative to positive: -x.

    Notes
    -----
    As a side effect, will round the number currently being input to the
    precision in the Decimal context.
    """

    try:
        update_current_calc(self, func=CalculatorFunctions.NEGATION)
    except Exception as e:
        logerror(e, "invert_sign", 2)
        self.bell()
