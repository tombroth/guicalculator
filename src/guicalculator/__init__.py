from decimal import Decimal
from unicodedata import normalize

BACKSPACE = "\u232B"
XSQUARED = "x\u00b2"
SQUAREROOTX = "\u221ax"
PI = "\u03c0"

FONT = ("TkDefaultFont", "12", "bold")

# stores default variables pi and e
# including first 30 digits because default precision is 28 in Decimal
# hard coding instead of using math.pi due to float to Decimal rounding issues
DEFAULT_VARIABLES: dict[str, Decimal] = {
    normalize("NFKC", PI): Decimal("3.141592653589793238462643383279"),
    "e": Decimal("2.718281828459045235360287471352"),
}
