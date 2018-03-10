Process that used to be victim process for APC DLL
injection technique.

Since APC DLL injection can be used only on threads 
that are waiting for event, this process uses SleepEx
to simulate process that is waiting for asynchronous 
event to signal.