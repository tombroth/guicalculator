from decimal import Decimal
from typing import NewType
from unicodedata import normalize

BACKSPACE = "\u232B"
XSQUARED = "x\u00b2"
SQUAREROOTX = "\u221ax"
XTOTHEY = "x ** y"
PI = "\u03c0"

FONT = ("TkDefaultFont", "12", "bold")


VariablesType = NewType("VariablesType", dict[str, Decimal])
"""Type to store varaibles and values for the parser: dict[str, Decimal]"""

# stores default variables pi and e
# including first 30 digits because default precision is 28 in Decimal
# hard coding instead of using math.pi due to float to Decimal rounding issues
DEFAULT_VARIABLES: VariablesType = VariablesType(
    {
        normalize("NFKC", PI): Decimal("3.141592653589793238462643383279"),
        "e": Decimal("2.718281828459045235360287471352"),
    }
)
