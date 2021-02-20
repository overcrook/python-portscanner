#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <structmember.h>

#include <stddef.h>
#include <portscan.h>
#include "python_portscan.h"

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

int register_portscan_result(PyObject *mod)
{
	// Завершение инициализации структуры
	if (PyType_Ready(&portscan_result_Type) < 0)
		return -1;

	Py_INCREF(&portscan_result_Type);
	PyModule_AddObject(mod, "result", (PyObject *) &portscan_result_Type);
	return 0;
}
