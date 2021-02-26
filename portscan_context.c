#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <structmember.h>

#include <stddef.h>
#include <portscan.h>
#include "python_portscan.h"

static void portscan_context_dealloc(struct py_portscan_context *self)
{
	portscan_cleanup(self->ctx);
	Py_TYPE(self)->tp_free((PyObject*)self);
}

static inline void portscan_context_reset(struct py_portscan_context *self)
{
	self->ctx      = NULL;
	self->result   = NULL;
	self->events   = 0;
	self->scan_fd  = -1;
	self->timer_fd = -1;
}

static PyObject *portscan_context_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	struct py_portscan_context *self;

	self = (struct py_portscan_context *)type->tp_alloc(type, 0);

	if (self != NULL)
		portscan_context_reset(self);

	return (PyObject *)self;
}

static int portscan_context_init(struct py_portscan_context *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {"address", "port_start", "port_end", "src_address", NULL};
	const char *src_address = NULL;
	const char *dst_address = NULL;
	unsigned int port_start = 0;
	unsigned int port_end   = 0;

	if (! PyArg_ParseTupleAndKeywords(args, kwds, "|sIIs", kwlist, &dst_address, &port_start, &port_end, &src_address))
		return -1;


	if (port_start < 1 || port_start > 65535) {
		PyErr_SetString(PyExc_ValueError, "'port_start' must be in range [1-65535]");
		return -1;
	}

	if (port_end > 0) {
		if (port_end > 65535) {
			PyErr_SetString(PyExc_ValueError, "'port_end' must be in range [1-65535]");
			return -1;
		}

		if (port_end < port_start) {
			PyErr_SetString(PyExc_ValueError, "'port_end' must be greater than 'port_start'");
			return -1;
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

	self->ctx = portscan_prepare(&req, result);

	if (!self->ctx) {
		free(result);
		PyErr_SetString(PyExc_RuntimeError, "Error while preparing scanner");
		return -1;
	}

	self->result       = result;
	self->result_count = port_count;
	self->scan_fd      = portscan_scanfd(self->ctx);
	self->timer_fd     = portscan_timerfd(self->ctx);
	self->events       = portscan_wanted_events(self->ctx);

	return 0;
}

static struct PyMemberDef portscan_context_members[] = {
	{"scan_fd",  T_INT, offsetof(struct py_portscan_context, scan_fd), 0, "fd"},
	{"timer_fd", T_INT, offsetof(struct py_portscan_context, timer_fd), 0, "fd"},
	{"events",   T_INT, offsetof(struct py_portscan_context, events), 0, "POLLIN|POLLOUT"},
	{NULL}
};

static PyObject* portscan_context_read(PyObject *self, PyObject *args)
{
	(void) args;
	struct py_portscan_context *st = (struct py_portscan_context *) self;

	if (!st->ctx) {
		PyErr_SetString(PyExc_RuntimeError, "Context already closed");
		return NULL;
	}

	int ret = portscan_pollin(st->ctx);

	if (ret < 0) {
		PyErr_SetString(PyExc_RuntimeError, "Error while reading from socket");
		return NULL;
	}

	st->events = ret == 0 ? 0 : portscan_wanted_events(st->ctx);
	Py_RETURN_NONE;
}

static PyObject* portscan_context_write(PyObject *self, PyObject *args)
{
	(void) args;
	struct py_portscan_context *st = (struct py_portscan_context *) self;

	if (!st->ctx) {
		PyErr_SetString(PyExc_RuntimeError, "Context already closed");
		return NULL;
	}

	int ret = portscan_pollout(st->ctx);

	if (ret < 0) {
		PyErr_SetString(PyExc_RuntimeError, "Error while writing to socket");
		return NULL;
	}

	st->events = ret == 0 ? 0 : portscan_wanted_events(st->ctx);
	Py_RETURN_NONE;
}

static PyObject* portscan_context_timeout(PyObject *self, PyObject *args)
{
	(void) args;
	struct py_portscan_context *st = (struct py_portscan_context *) self;

	if (!st->ctx) {
		PyErr_SetString(PyExc_RuntimeError, "Context already closed");
		return NULL;
	}

	int ret = portscan_timeout(st->ctx);

	if (ret < 0) {
		PyErr_SetString(PyExc_RuntimeError, "Error while processing timeout");
		return NULL;
	}

	st->events = ret == 0 ? 0 : portscan_wanted_events(st->ctx);
	Py_RETURN_NONE;
}

static PyObject* portscan_context_close(PyObject *self, PyObject *args)
{
	(void) args;
	struct py_portscan_context *st = (struct py_portscan_context *) self;

	if (!st->ctx) {
		PyErr_SetString(PyExc_RuntimeError, "Context already closed");
		return NULL;
	}

	PyObject *python_result = PyList_New(st->result_count);

	for (int i = 0; i < st->result_count; i++) {
		PyObject *argList = Py_BuildValue("is", st->result[i].port, portscan_strstatus(st->result[i].status));
		PyObject *item = PyObject_CallObject((PyObject *) &portscan_result_Type, argList);
		PyList_SetItem(python_result, i, item);
		Py_DECREF(argList);
	}

	free(st->result);
	portscan_cleanup(st->ctx);
	portscan_context_reset(st);
	return python_result;
}

static PyMethodDef portscan_context_methods[] = {
	{"read",    portscan_context_read,    METH_NOARGS, "doc string"},
	{"write",   portscan_context_write,   METH_NOARGS, "doc string"},
	{"timeout", portscan_context_timeout, METH_NOARGS, "doc string"},
	{"close",   portscan_context_close,   METH_NOARGS, "doc string"},
	{NULL}  /* Sentinel */
};

PyTypeObject portscan_context_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name      = "portscan.context",
	.tp_basicsize = sizeof(struct py_portscan_context),
	.tp_dealloc = (destructor) portscan_context_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_doc = "portscan_context objects",
	.tp_methods = portscan_context_methods,
	.tp_members = portscan_context_members,
	.tp_init = (initproc) portscan_context_init,
	.tp_new = portscan_context_new,
};

int register_portscan_context(PyObject *mod)
{
	// Завершение инициализации структуры
	if (PyType_Ready(&portscan_context_Type) < 0)
		return -1;

	Py_INCREF(&portscan_context_Type);
	PyModule_AddObject(mod, "new", (PyObject *) &portscan_context_Type);

	// Добавляем необходимые статические переменные модуля, чтобы не было протечек особенностей реализации
	PyModule_AddObject(mod, "POLLIN",  PyLong_FromLong(POLLIN));
	PyModule_AddObject(mod, "POLLOUT", PyLong_FromLong(POLLOUT));

	return 0;
}
