#include <Python.h>

// g++ $(python-config --cflags) -o test $(python-config --ldflags) ./test.cpp

int main()
{
	/// Vars ///
	char *inputArg = (char *)"0800000010410025035685570000000040020a0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637";
	const char *fileName = "NetworkPacketFunctions";
	char *path = (char *)".";
    char *packetCalcChecksumResult;
    char *packetSequenceNoIncrementResult;
    PyObject *module, *func, *prm, *ret;

	/// Initialize Python interpreter ///
    Py_Initialize();
    PyRun_SimpleString("import scapy.utils");

	/// Sets the working path to the current path ///
    PySys_SetPath(path);
	
	/// Import of the script-file, note that the actual script name is "script.py" ///
    module = PyImport_ImportModule(fileName);
    PyErr_Print();

	/// Check to make sure the script was loaded ///
    if (module != 0)
    {
		/// Opens a function within the python script. Notice that you must use a function within the python script, because otherwise you can't return anything. ///
        func = PyObject_GetAttrString(module, "packetCalcChecksum");
      
        /// The "(ss)" means two strings are passed (replace with "i" for integer for instance), the "Hello" and "Mars" are the strings i pass to the script. ///
        //prm = Py_BuildValue("(ss)", "Hello", "Mars");
        prm = Py_BuildValue("(s)", inputArg);
        
        /// Returns some python object i have literally no idea about ... ///
        ret = PyObject_CallObject(func, prm);

		/// Cast result back to a c-compatible char* ///
        packetCalcChecksumResult = PyString_AsString(ret);
        
        
        ///////////////////////////////////////////////////////////////
        
        func = PyObject_GetAttrString(module, "packetSequenceNoIncrement");
      
        /// The "(ss)" means two strings are passed (replace with "i" for integer for instance), the "Hello" and "Mars" are the strings i pass to the script. ///
        //prm = Py_BuildValue("(ss)", "Hello", "Mars");
        prm = Py_BuildValue("(s)", inputArg);
        
        /// Returns some python object i have literally no idea about ... ///
        ret = PyObject_CallObject(func, prm);
        
        /// Cast result back to a c-compatible char* ///
        packetSequenceNoIncrementResult = PyString_AsString(ret);
        
        ///////////////////////////////////////////////////////////////
        
        
        printf("Passed '%s' to python script!\n\n", inputArg);
        printf("Received '%s' back from packetCalcChecksum function!\n\n", packetCalcChecksumResult);
        printf("Received '%s' back from packetSequenceNoIncrement function!\n\n", packetSequenceNoIncrementResult);

		/// Clean up? ///
        Py_DECREF(module);
        Py_DECREF(func);
        Py_DECREF(prm);
        Py_DECREF(ret);
    }
    /// Error out: No script found //
    else 
    {
        printf("Error: No script file named \"%s.py\" was found!\n", fileName);
    }

    Py_Finalize();
    return 0;	
}
