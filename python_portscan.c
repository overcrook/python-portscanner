#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <structmember.h>

#include <stddef.h>
#include <portscan.h>

struct py_portscan_result {
	PyObject_HEAD // Макрос объявления нового типа, объекта фиксированного размера
	int port;
	const char *status;
};

static void portscan_result_dealloc(struct py_portscan_result *self)
{
	Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *portscan_result_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	struct py_portscan_result *self;

	self = (struct py_portscan_result *)type->tp_alloc(type, 0);

	if (self != NULL) {
		self->port = 0;
		self->status = portscan_strstatus(PORT_STATUS_FILTERED);
	}

	return (PyObject *)self;
}

static int portscan_result_init(struct py_portscan_result *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {"port", "status", NULL};
	const char *status = NULL;

	if (! PyArg_ParseTupleAndKeywords(args, kwds, "|is", kwlist, &self->port, &status))
		return -1;

	if (status) {
		enum port_status st = -1;

		if (strcasecmp(status, "open") == 0)
			st = PORT_STATUS_OPEN;
		else if (strcasecmp(status, "closed") == 0)
			st = PORT_STATUS_CLOSED;
		else if (strcasecmp(status, "filtered") == 0)
			st = PORT_STATUS_FILTERED;

		if ((int) st == -1) {
			PyErr_SetString(PyExc_ValueError, "'status' must be one of [open, closed, filtered]");
			return -1;
		}

		self->status = portscan_strstatus(st);
	}

	return 0;
}

static struct PyMemberDef portscan_result_members[] = {
	{"port", T_INT, offsetof(struct py_portscan_result, port), 0, "int"},
	{"status", T_STRING, offsetof(struct py_portscan_result, status), 0, "string"},
	{NULL}
};

static PyObject* portscan_result_print(PyObject *self, PyObject *args)
{
	(void) args;
	struct py_portscan_result *st = (struct py_portscan_result *) self;

	printf(" %d  \t%s\n", st->port, st->status);
	Py_RETURN_NONE;
}

static PyMethodDef portscan_result_methods[] = {
	{"print", portscan_result_print, METH_NOARGS, "doc string"},
	{NULL}  /* Sentinel */
};

PyTypeObject portscan_result_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name      = "portscan.result",
	.tp_basicsize = sizeof(struct py_portscan_result),
	.tp_dealloc = (destructor) portscan_result_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_doc = "portscan_result objects",
	.tp_methods = portscan_result_methods,
	.tp_members = portscan_result_members,
	.tp_init = (initproc) portscan_result_init,
	.tp_new = portscan_result_new,
};

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

	// Завершение инициализации структуры
	if (PyType_Ready(&portscan_result_Type) < 0)
		return NULL;

	Py_INCREF(&portscan_result_Type);
	PyModule_AddObject(mod, "result", (PyObject *) &portscan_result_Type);

	return mod;
}
