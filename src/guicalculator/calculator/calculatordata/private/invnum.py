from ....globals import CalculatorFunctions
from ...logwrapper import logerror, object_wrapper
from ..calculatordata import CalculatorData
from .updatecalc import update_current_calc


@object_wrapper
def inverse_number(self: CalculatorData) -> None:
    """
    inverse_number - Convert the current number being input to it's
    mathematical inverse: 1/x.

    Notes
    -----
    As a side effect, will round the number currently being input to the
    precision in the Decimal context.
    """

    try:
        update_current_calc(self, func=CalculatorFunctions.INVERSION)
    except Exception as e:
        logerror(e, "inverse_number", 2)
        self.bell()
