from ....globals import DEFAULT_VARIABLES
from ...logwrapper import object_wrapper
from ..calculatordata import CalculatorData


@object_wrapper
def get_user_variable_names(
    self: CalculatorData, include_default: bool = True
) -> list[str]:
    """
    get_user_variable_names - Return a list of current variable names

    Validates that user variable names are string, doesn't check for keywords,
    invalid identifier, duplicating a default variable, etc as that is done
    by validate_user_var.

    Parameters
    ----------
    include_default : bool, optional
        include the default variables (e and pi), by default True

    Returns
    -------
    list[str]
        The variable names
    """

    varnames: list[str] = []

    if include_default:
        varnames.extend([*DEFAULT_VARIABLES.keys()])

    # double checking that variable names are str
    # default variables are defined in code so should be safe
    for var in self._user_variables.keys():
        if isinstance(var, str):
            varnames.append(var)
        else:
            raise ValueError(f"User variable name is not str: {var!r}")

    return varnames
