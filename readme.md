EZGrsec
=======

Description
-----------
Automated Linux GRSec kernel downloaded, compiled, installed, and even RPM packaged.

Special Groups
-------------
~~~
Group GID 2000 grs-proc	This group is for non-root users that need access to the /proc system. Anyone that isn't root and not in this group will not be able to even see other users processes or who else is logged in.
Group GID 2001 grs-tpe	All users in this group are only able to exec files in root owned dirs writable by root, nothing more. Not even ~/bin/
Group GID 2002 grs-sock-all	Group to disable all socket access.
Group GID 2003 grs-sock-client	Group to disable all client only socket access.
Group GID 2004 grs-sock-sever	Group to disable all server only socket access.
Group GID 2005 grs-audit	Group to enforce full auditing through syslog. Logs exec, ptrace, mount, sig, and chdir of these users
~~~

