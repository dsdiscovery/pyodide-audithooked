#define PY_SSIZE_T_CLEAN
#include "Python.h"
#include <emscripten.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define FAIL_IF_STATUS_EXCEPTION(status)                                       \
  if (PyStatus_Exception(status)) {                                            \
    goto finally;                                                              \
  }

const char* allow_list[] = {
  "builtins.id",
  "code.__new__",
  "compile",
  "ctypes.dlopen",
  "exec",
  "gc.get_referents",
  "import",
  "marshal.loads",
  "object.__delattr__",
  "object.__getattr__",
  "object.__setattr__",
  "open",
  "os.listdir",
  "os.mkdir",
  "os.putenv",
  "os.remove",
  "os.scandir",
  "os.unsetenv",
  "pathlib.Path.glob",
  "shutil.unpack_archive",
  "sys._getframe",
  "sys._getframemodulename",
  "sys.excepthook",
  "tempfile.mkstemp",
};
const size_t allow_list_len = sizeof(allow_list) / sizeof(allow_list[0]);

PyObject* whitelist_set = NULL;
int
hook_func(const char* event, PyObject* args, void* userData)
{
  if (!whitelist_set) {
    whitelist_set = PySet_New(NULL);
    for (size_t i = 0; i < allow_list_len; i++) {
      PyObject* event = PyUnicode_FromString(allow_list[i]);
      PySet_Add(whitelist_set, event);
      Py_DECREF(event);
    }
    fflush(stderr);
  }

  bool malicious = false;

  PyObject* event_obj = PyUnicode_FromString(event);

  if (!event_obj) {
    PyErr_SetString(PyExc_RuntimeError, "Failed to create event object");
    return -1;
  }

  const int containment = PySet_Contains(whitelist_set, event_obj);
  Py_DECREF(event_obj);
  if (containment == -1) {
    PyErr_SetString(PyExc_RuntimeError, "Failed to check containment");
    return -1;
  } else if (containment == 0) {
    malicious = true;
  }
  if (malicious) {
    PyErr_SetString(PyExc_RuntimeError, "EPERM: Operation not permitted");
    return -1;
  } else {
    return 0;
  }
}

// Initialize python. exit() and print message to stderr on failure.
static void
initialize_python(int argc, char** argv)
{
  bool success = false;
  PyStatus status;

  PyPreConfig preconfig;
  PyPreConfig_InitPythonConfig(&preconfig);

  status = Py_PreInitializeFromBytesArgs(&preconfig, argc, argv);
  FAIL_IF_STATUS_EXCEPTION(status);

  PyConfig config;
  PyConfig_InitPythonConfig(&config);

  status = PyConfig_SetBytesArgv(&config, argc, argv);
  FAIL_IF_STATUS_EXCEPTION(status);

  status = PyConfig_SetBytesString(&config, &config.home, "/");
  FAIL_IF_STATUS_EXCEPTION(status);

  config.write_bytecode = false;
  PySys_AddAuditHook(hook_func, NULL);
  status = Py_InitializeFromConfig(&config);
  FAIL_IF_STATUS_EXCEPTION(status);

  success = true;
finally:
  PyConfig_Clear(&config);
  if (!success) {
    // This will exit().
    Py_ExitStatusException(status);
  }
}

PyObject*
PyInit__pyodide_core(void);

/**
 * Bootstrap steps here:
 *  1. Import _pyodide package (we depend on this in _pyodide_core)
 *  2. Initialize the different ffi components and create the _pyodide_core
 *     module
 *  3. Create a PyProxy wrapper around _pyodide package so that JavaScript can
 *     call into _pyodide._base.eval_code and
 *     _pyodide._import_hook.register_js_finder (this happens in loadPyodide
 * in pyodide.js)
 */
int
main(int argc, char** argv)
{
  // This exits and prints a message to stderr on failure,
  // no status code to check.
  PyImport_AppendInittab("_pyodide_core", PyInit__pyodide_core);
  initialize_python(argc, argv);
  emscripten_exit_with_live_runtime();
  return 0;
}

void
pymain_run_python(int* exitcode);

EMSCRIPTEN_KEEPALIVE int
run_main()
{
  int exitcode;
  pymain_run_python(&exitcode);
  return exitcode;
}
