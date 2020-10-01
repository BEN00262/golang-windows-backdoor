# golang-not-stealthy-backdoor
This is a backdoor created with golang its not FUD will be working on it later

### compiling and running
to compile just **_run make in the folder where the Makefile is located_** or if you dont have a make run **_go build -ldflags="-s -w -H=windowsgui" advancedrerverseshell.go_** and for the master **_go build -ldflags="-s -w" master.go_**

### design of the RAT
the RAT uses UAC bypass techniques to render an admin cmd.exe
the traffic is **tls wrapped** to provide some security on the communications

### Issues
On disconnecting the master the client does not reconnect back until the client is restarted again **will solve this on the next update**

### supported platform
The RAT only works on windows platforms (x64) but the master can be compiled and run from anywhere 

### future developments and contribution
Am still working on antivirus evasion techniques.
All contributions are welcomed. Feel free to fork and contribute to the code 

### Happy hacking!!! :smile:
