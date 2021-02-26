#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <structmember.h>

#include <stddef.h>
#include <portscan.h>
#include "python_portscan.h"

static PyObject *portscan(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {"address", "port_start", "port_end", "src_address", NULL};
	const char *src_address = NULL;
	const char *dst_address = NULL;
	int port_start = 0;
	int port_end = 0;

	(void) self;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "sI|Is", kwlist, &dst_address, &port_start, &port_end, &src_address))
		return NULL;

	if (port_start < 1 || port_start > 65535) {
		PyErr_SetString(PyExc_ValueError, "'port_start' must be in range [1-65535]");
		return NULL;
	}

	if (port_end > 0) {
		if (port_end > 65535) {
			PyErr_SetString(PyExc_ValueError, "'port_end' must be in range [1-65535]");
			return NULL;
		}

		if (port_end < port_start) {
			PyErr_SetString(PyExc_ValueError, "'port_end' must be greater than 'port_start'");
			return NULL;
		}
	} else {
		port_end = port_start;
	}

	int port_count = port_end - port_start + 1;
	struct portscan_result *result = malloc(sizeof(struct portscan_result) * port_count);

	struct portscan_req req = {
		.src_ip     = src_address,
		.dst_ip     = dst_address,
		.port_start = port_start,
		.port_end   = port_end
	};

	int err = portscan_execute(&req, result);

	if (err) {
		PyErr_SetString(PyExc_RuntimeError, "Error running port scanner");
		free(result);
		return NULL;
	}

	PyObject* python_result = PyList_New(port_count);

	for (int i = 0; i < port_count; i++) {
		PyObject *argList = Py_BuildValue("is", result[i].port, portscan_strstatus(result[i].status));
		PyObject *item = PyObject_CallObject((PyObject *) &portscan_result_Type, argList);
		PyList_SetItem(python_result, i, item);
		Py_DECREF(argList);
	}

	free(result);
	return python_result;
}


static PyObject *version(PyObject *self, PyObject *args)
{
	(void) self;
	(void) args;

	return PyUnicode_FromString(portscan_version());
}

static PyMethodDef PortscanMethods[] = {
	{"scan",     (PyCFunction) portscan, METH_VARARGS | METH_KEYWORDS, "Execute a shell command."},
	{"version",  version,  METH_NOARGS,  "Returns a portscan version."},
	{NULL, NULL, 0, NULL}        /* Sentinel */
};

static struct PyModuleDef PortscanModule = {
	PyModuleDef_HEAD_INIT,
	"portscan",   /* name of module */
	NULL, /* module documentation, may be NULL */
	-1,       /* size of per-interpreter state of the module,
						 or -1 if the module keeps state in global variables. */
	PortscanMethods
};

PyMODINIT_FUNC
PyInit_portscan(void)
{
	PyObject *mod = PyModule_Create(&PortscanModule);

	if (register_portscan_result(mod))
		return NULL;

	if (register_portscan_context(mod))
		return NULL;

	return mod;
}
