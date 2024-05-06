"""
guicalculator/calculator/calculatordata/private - Calculator functions used 
internally by the calculator and not intended to be called from the user 
interface.

The files in this directory:

    backspace.py - The backspace function

    buttonpress.py - The button_press function
    
    calculate.py - The calculate function
    
    clearall.py - The clear_all function
    
    clearvalue.py - The clear_value function
    
    getcurinpt.py - The get_current_input function
    
    getmem.py - The get_current_memory function
    
    getnumfncsym.py - The get_num_fnc_sym function
    
    getuservarnames.py - The get_user_variable_names function
    
    invnum.py - The inverse_number function
    
    memadd.py - The memory_add function
    
    memclear.py - The memory_clear function
    
    memrecall.py - The memory_recall function
    
    memstore.py - The memory_store function
    
    memswap.py - The memory_swap function
    
    negate.py - The negate function
    
    rootnum.py - The root_number function
    
    squarenum.py - The square_number function
    
    types.py - The _CalcString* classes
    
    updatecalc.py - The update_current_calc function
    
    validatesymfunc.py - The validate_symbol_and_func function
"""

"""
Copyright (c) 2024 Thomas Brotherton

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

# nothing should be imported from this subproject
__all__: list[str] = []
