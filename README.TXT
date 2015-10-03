Registry Redirector

 (C)oded by leecher@dose.0wnz.at, 2010

This application redirects registry calls to Registry dump
files, so that you can "shim" your application to a foreign
registry.

This may become handy if you want to check the registry
of another machine with various checking tools that are
designed for the checking of a live System.
Note that the application must use the normal WIN32 API
for registry Access. If the app is checking via Native API,
this won't work.

Be aware that reads AND WRITES are redirected, so only
use this tool on copies of your original Registry files.
It may be a good idea to use this tool in a PE environment.

If you have questions or comments, just feel free to contact me.