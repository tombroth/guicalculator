from typing import List, NamedTuple, NotRequired, TypedDict

from guicalculator import BACKSPACE, SQUAREROOTX, XSQUARED


class ButtonLocation(NamedTuple):
    """
    ButtonLocation - Where to locate a button on the calculator

    Parameters
    ----------
    NamedTuple : A tuple consisting of:
        btnfrm : int
            This indicates which sub-frame of BtnDispFrm to put the button
            into. Subframes are used to group rows with the same number of
            buttons. The first subframe is 0.
        btnrow : int
            This indicates which row in the sub-frame the button is placed
            on. The first row of a new sub-frame is 0.
        btncol : int
            This indicates which column in the row the button is placed on.
            The first column of a new sub-frame is 0.
    """

    btnfrm: int
    btnrow: int
    btncol: int


class ButtonInfo(TypedDict):
    """
    ButtonInfo - Information needed to create a button on the calculator.

    Parameters
    ----------
    TypedDict : A dictionary consisting of:
        label : str | int
            Mandatory. The button text. Number buttons should be int,
            everything else a str.
        command : NotRequired[str]
            Optional. Which command to execute. No command is needed for
            basic number and math operators. Commands are decoded by the
            processbutton funciton in CalcFrm in guicalculator.py.
        style : NotRequired[str]
            Optional. Style information for the button. Styles are found
            in CalcStyle in guicalculator.py.
        rowspan : NotRequired[int]
            Optional. This is the rowspan parameter of the grid call.
        columnspan : NotRequired[int]
            Optional. This is the columnspan parameter of the grid call.
        events : NotRequired[List[str]]
            Optional. This is a list of events bound to this button.invoke,
            bound at winfo_toplevel.
    """

    label: str | int
    command: NotRequired[str]
    style: NotRequired[str]
    rowspan: NotRequired[int]
    columnspan: NotRequired[int]
    events: NotRequired[List[str]]


# The calculator buttons
buttons: dict[ButtonLocation, ButtonInfo] = {
    ButtonLocation(0, 0, 0): {
        "label": BACKSPACE,
        "command": "backspace",
        "style": "red.TButton",
        "events": ["<BackSpace>"],
    },
    ButtonLocation(0, 0, 1): {
        "label": "CE",
        "command": "clearValue",
        "style": "red.TButton",
        "events": ["<KeyPress-C>", "<KeyPress-c>"],
    },
    ButtonLocation(0, 0, 2): {
        "label": "AC",
        "command": "clearAll",
        "style": "red.TButton",
    },
    ButtonLocation(1, 0, 0): {
        "label": "MClr",
        "command": "memClear",
        "style": "memory.TButton",
    },
    ButtonLocation(1, 0, 1): {
        "label": "MRcl",
        "command": "memRecall",
        "style": "memory.TButton",
    },
    ButtonLocation(1, 0, 2): {
        "label": "MSto",
        "command": "memStore",
        "style": "memory.TButton",
    },
    ButtonLocation(1, 0, 3): {
        "label": "MSwp",
        "command": "memSwap",
        "style": "memory.TButton",
    },
    ButtonLocation(1, 0, 4): {
        "label": "M+",
        "command": "memAdd",
        "style": "memory.TButton",
    },
    ButtonLocation(1, 0, 5): {
        "label": "M-",
        "command": "memSubtract",
        "style": "memory.TButton",
    },
    ButtonLocation(2, 0, 0): {
        "label": "1/x",
        "command": "inverseNumber",
    },
    ButtonLocation(2, 0, 1): {
        "label": XSQUARED,
        "command": "squareNumber",
    },
    ButtonLocation(2, 0, 2): {
        "label": SQUAREROOTX,
        "command": "rootNumber",
    },
    ButtonLocation(2, 0, 3): {
        "label": "/",
        "style": "mathop.TButton",
        "events": ["<KeyPress-/>"],
    },
    ButtonLocation(2, 1, 0): {
        "label": "vars...",
        "command": "varsPopup",
    },
    ButtonLocation(2, 1, 1): {
        "label": "(",
        "events": ["<KeyPress-(>"],
    },
    ButtonLocation(2, 1, 2): {
        "label": ")",
        "events": ["<KeyPress-)>"],
    },
    ButtonLocation(2, 1, 3): {
        "label": "*",
        "style": "mathop.TButton",
        "events": ["<KeyPress-*>"],
    },
    ButtonLocation(2, 2, 0): {
        "label": 7,
        "style": "number.TButton",
        "events": ["<KeyPress-7>"],
    },
    ButtonLocation(2, 2, 1): {
        "label": 8,
        "style": "number.TButton",
        "events": ["<KeyPress-8>"],
    },
    ButtonLocation(2, 2, 2): {
        "label": 9,
        "style": "number.TButton",
        "events": ["<KeyPress-9>"],
    },
    ButtonLocation(2, 2, 3): {
        "label": "-",
        "style": "mathop.TButton",
        "events": ["<KeyPress-minus>"],
    },
    ButtonLocation(2, 3, 0): {
        "label": 4,
        "style": "number.TButton",
        "events": ["<KeyPress-4>"],
    },
    ButtonLocation(2, 3, 1): {
        "label": 5,
        "style": "number.TButton",
        "events": ["<KeyPress-5>"],
    },
    ButtonLocation(2, 3, 2): {
        "label": 6,
        "style": "number.TButton",
        "events": ["<KeyPress-6>"],
    },
    ButtonLocation(2, 3, 3): {
        "label": "+",
        "style": "mathop.TButton",
        "events": ["<KeyPress-+>"],
    },
    ButtonLocation(2, 4, 0): {
        "label": 1,
        "style": "number.TButton",
        "events": ["<KeyPress-1>"],
    },
    ButtonLocation(2, 4, 1): {
        "label": 2,
        "style": "number.TButton",
        "events": ["<KeyPress-2>"],
    },
    ButtonLocation(2, 4, 2): {
        "label": 3,
        "style": "number.TButton",
        "events": ["<KeyPress-3>"],
    },
    ButtonLocation(2, 4, 3): {
        "label": "=",
        "command": "calculate",
        "style": "orange.TButton",
        "rowspan": 2,
        "events": ["<KeyPress-=>", "<Return>"],
    },
    ButtonLocation(2, 5, 0): {
        "label": "+/-",
        "command": "invertSign",
        "style": "number.TButton",
    },
    ButtonLocation(2, 5, 1): {
        "label": 0,
        "style": "number.TButton",
        "events": ["<KeyPress-0>"],
    },
    ButtonLocation(2, 5, 2): {
        "label": ".",
        "style": "number.TButton",
        "events": ["<KeyPress-.>"],
    },
}
