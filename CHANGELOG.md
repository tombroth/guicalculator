# Change Log


## [0.1.3] - 2024-05-07

- Several minor improvements
- Moved the calculator data object that had all the calculator functions into a subproject, split apart the functions into separate files ([#15](https://github.com/tombroth/guicalculator/issues/15))
- Added explicit multiplication operators where implied multiplication would exist ([#14](https://github.com/tombroth/guicalculator/issues/14))
- Refactored most calculator functions ([#13](https://github.com/tombroth/guicalculator/issues/13))
- Refactored how the current calculation is stored ([#12](https://github.com/tombroth/guicalculator/issues/12))
- Added logging ([#4](https://github.com/tombroth/guicalculator/issues/4))
- Updated handling of no input on various functions ([#10](https://github.com/tombroth/guicalculator/issues/10))
- Changed the calculator state variables to be protected ([#11](https://github.com/tombroth/guicalculator/issues/11))
- Reorganized the codebase to fit into three top level directories: calculator, globals, and gui ([#6](https://github.com/tombroth/guicalculator/issues/6))
- Changed "Add current result as new variable" to call the parser directly, not updating the calculator state, and displaying an error message if there was an error ([#9](https://github.com/tombroth/guicalculator/issues/9))
- Added enumerations and constants for several strings ([#8](https://github.com/tombroth/guicalculator/issues/8))
- Changed classes to not inherit from Tk objects but to contain a Tk object ([#7](https://github.com/tombroth/guicalculator/issues/7))
- Created new module calculatordata.py to contain calculator data and functions ([#7](https://github.com/tombroth/guicalculator/issues/7))
- Created unit tests for calculatordata.py ([#7](https://github.com/tombroth/guicalculator/issues/7))


## [0.1.2] - 2024-04-23

- Several minor improvements
- Added module level docstrings to each file
- Added exponentiation (x ** y)
- Updated square, square root, and inverse to add to calculation instead of being immediate
- Added a double click action to the variables popup window
- Moved the parser functions into supportfuncs.py and added tests for parser ([#3](https://github.com/tombroth/guicalculator/issues/3))
- Split default variables and user variables ([#5](https://github.com/tombroth/guicalculator/issues/5))
- Reworked buttoncfg.py ([#2](https://github.com/tombroth/guicalculator/issues/2))
- Moved operator map out of buttoncfg.py ([#1](https://github.com/tombroth/guicalculator/issues/1))


## [0.1.1] - 2024-04-18

### Fixed

- Fixed issue with scroll bar not resizing in the variables popup window
- Updated README.md


## [0.1.0] - 2024-04-17

Initial release