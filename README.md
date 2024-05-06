## Description
There is some a crypter with a shitty stub and with the sections ".[1]" and ".[0]" that performs one anti debug check and Process Hollowing to execute the encrypted binary inside of it.
I wrote something in order to extract the encrypted binary.

## Usage 
1. nameofthetool.exe "path to the binary" ...(you can provide multiple path if you wanna use it on multiple binaries at once)

## Images cause why not
- Entry point 


![](img/entrypoint.png)
- Sections


![](img/sections.png)