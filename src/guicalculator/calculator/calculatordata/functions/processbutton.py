from ....globals import CalculatorCommands, CalculatorSymbols
from ...logwrapper import object_wrapper
from ..calculatordata import CalculatorData
from ..private.backspace import backspace
from ..private.buttonpress import button_press
from ..private.calculate import calculate
from ..private.clearall import clear_all
from ..private.clearvalue import clear_value
from ..private.invnum import inverse_number
from ..private.memadd import memory_add
from ..private.memclear import memory_clear
from ..private.memrecall import memory_recall
from ..private.memstore import memory_store
from ..private.memswap import memory_swap
from ..private.negate import negate
from ..private.rootnum import root_number
from ..private.squarenum import square_number


@object_wrapper
def process_button(
    self: CalculatorData,
    buttoncmd: CalculatorCommands,
    buttontxt: str | int = "",
) -> None:
    """
    process_button - Process a calculator button press.

    Parameters
    ----------
    buttoncmd : str
        The command string from the ButtonInfo dictionary in
        buttoncfg.py buttons.
    buttontxt : str | int, optional
        For buttons in buttoncfg.py that don't have a command
        (number and basic math symbols) this is the button label,
        can also be used to pass default or user variables, or
        calculator symbols like ** that aren't necessarily labels,
        by default ""
    """

    match buttoncmd:
        case CalculatorCommands.BASICBUTTON:
            button_press(self, buttontxt)

        case CalculatorCommands.BACKSPACE:
            backspace(self)

        case CalculatorCommands.CALCULATE:
            calculate(self)

        case CalculatorCommands.CLEARALL:
            clear_all(self)

        case CalculatorCommands.CLEARVALUE:
            clear_value(self)

        case CalculatorCommands.INVERSENUMBER:
            inverse_number(self)

        case CalculatorCommands.NEGATE:
            negate(self)

        case CalculatorCommands.MEMADD:
            memory_add(self)

        case CalculatorCommands.MEMCLEAR:
            memory_clear(self)

        case CalculatorCommands.MEMRECALL:
            memory_recall(self)

        case CalculatorCommands.MEMSTORE:
            memory_store(self)

        case CalculatorCommands.MEMSUBTRACT:
            memory_add(self, False)

        case CalculatorCommands.MEMSWAP:
            memory_swap(self)

        case CalculatorCommands.ROOTNUMBER:
            root_number(self)

        case CalculatorCommands.SQUARENUMBER:
            square_number(self)

        case CalculatorCommands.VARSPOPUP:
            self.vars_popup()

        case CalculatorCommands.XTOTHEY:
            button_press(self, CalculatorSymbols.EXPONENTIATION)

        case _:
            self.bell()
            raise ValueError(f"Unknown command: {buttoncmd!r}")
