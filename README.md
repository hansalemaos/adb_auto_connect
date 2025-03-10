# adb_auto_connect
Check constantly for new ADB devices and connect them

## Compile with [ZIG](https://ziglang.org/) or [GCC](https://www.gnu.org/) the code or use `adbconnect.exe` 

```sh
zig c++ -std=c++2a -O3 -g0 adbconnect.cpp -o adbconnect.exe
```

## All arguments are optional

```sh
Command-Line Arguments:
-----------------------
--adb_path:
    Specifies the path to the ADB executable.
    Default:  --adb_path=adb

--min_port:
    Sets the minimum port number to consider when scanning for connections. Ports below this value will be ignored.
    Default:  --min_port=5550

--limit_port:
    When set to a non-zero value, enables port limiting by configuring an environment variable for ADB.
    Default:  --limit_port=1

--print_output:
    Controls verbosity. A non-zero value enables detailed log messages and colored output.
    Default:  --print_output=0

--sleep_after_connect:
    Sets the delay (in milliseconds) after initiating connection commands, allowing time for processing.
    Default:  --sleep_after_connect=2000

--sleep_after_loop:
    Specifies the delay (in milliseconds) after completing one full cycle of scanning and connecting before restarting the loop.
    Default:  --sleep_after_loop=1000

--help=1:
    Displays this help message and exits.
```