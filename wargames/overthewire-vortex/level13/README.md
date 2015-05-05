# Vortex 13

Format string fun for a multiple GOT overwrite.  It also nulls out the args and environment.  For whatever reason, libc puts a copy of `basename(argv[0])` on the stack, so we store our pointers there.

An alternative solution is provided taking control with a single overwrite and returning to libc.
