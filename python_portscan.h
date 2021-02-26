#define PY_SSIZE_T_CLEAN
#include <Python.h>


struct py_portscan_result {
	PyObject_HEAD // Макрос объявления нового типа, объекта фиксированного размера
	int port;
	const char *status;
};

extern PyTypeObject portscan_result_Type;

int register_portscan_result(PyObject *mod);


struct py_portscan_context {
	PyObject_HEAD // Макрос объявления нового типа, объекта фиксированного размера
	struct portscan_context *ctx;
	struct portscan_result *result;
	int result_count;
	int scan_fd;
	int timer_fd;
	int events;
};

extern PyTypeObject portscan_context_Type;

int register_portscan_context(PyObject *mod);
