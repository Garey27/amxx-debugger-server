# AMX Mod X Debug Server [WIP]
[![Build status](https://ci.appveyor.com/api/projects/status/vu3fovmx1082ioff?svg=true)](https://ci.appveyor.com/project/Garey/amxx-debugger-server)

This is a debug server for Amxx which allows for remote debugging of scripts. At this time implemented only VSCode adapter for this server.

## Build and Run

* Clone the project and build it. Or download release from github.
* Add "debugger" to "addons\amxmodx\configs\modules.ini"
* Start hlds server
* Follow readme from (https://github.com/Garey27/vscode-amxx-debug) to debug with Visual Studio Code

## TODO

- [ ] Test on linux
- [ ] Change hardcode port 1234 to cvar or config.
- [ ] Add API to AMXX?

