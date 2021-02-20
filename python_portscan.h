#define PY_SSIZE_T_CLEAN
#include <Python.h>


struct py_portscan_result {
	PyObject_HEAD // Макрос объявления нового типа, объекта фиксированного размера
	int port;
	const char *status;
};

extern PyTypeObject portscan_result_Type;

int register_portscan_result(PyObject *mod);
