from distutils.core import setup, Extension

module1 = Extension('portscan',
                    define_macros = [('MAJOR_VERSION', '1'),
                                     ('MINOR_VERSION', '0')],
                    include_dirs = ['/usr/local/include', 'submodule/portscanner/include'],
                    libraries = ['portscanner'],
                    library_dirs = ['/usr/local/lib', 'submodule/portscanner/build'],
                    sources = ['python_portscan.c', 'portscan_result.c', 'portscan_context.c'])

setup (name = 'Portscanner',
       version = '1.0',
       description = 'This is a demo package',
       author = 'Alexander Safonov',
       author_email = 'al.safonov@inbox.ru',
       ext_modules = [module1])
