# GoodbyeEDR
███████████████████████████████████████████████████████
█────█────█────█────██────██──█──█───███───█────██────█
█─████─██─█─██─█─██──█─██──██───██─█████─███─██──█─██─█
█─█──█─██─█─██─█─██──█────████─███───███───█─██──█────█
█─██─█─██─█─██─█─██──█─██──███─███─█████─███─██──█─█─██
█────█────█────█────██────████─███───███───█────██─█─██
██████████████████████████████─████████████████████████

## Info
Disable & hook notifications of AV & EDR from events occurring in the system.

The project has the following features:
1. List 
    - callbacks;
    - minifilters.
3. Removing callback functions:
    - create/exit of processes;
    - create/exit of threads.
4. Hook callback functions with filtering by process name:
    - create/exit of processes;
    - create/exit of threads.
5. Hook file system minifilters.
6. Abuse AV & EDR after remove or hook.
    
The assembly is a compilation of two great projects:
1. https://github.com/uf0o/windows-ps-callbacks-experiments (Fork deleted repository https://github.com/fdiskyou/windows-ps-callbacks-experiments).
2. https://github.com/SHA-MRIZ/FsMinfilterHooking
    
Additionally, added the ability to hook callback functions with filtering by the name of the process: create/exit of processes and threads & hook of file system minifilters.

## Build
The project is built for Visual Studio 2019 with SDK & DDK v10.0.22000.0 for x64.

## Install

After built put all files together in one directory and place the same directory install.bat:
- `Dobro.sys` - driver
- `DobroCli.exe` - cli for control driver
- `Install.bat` - install

Run install.bat as administrator.

Start driver: `sc start dobro`

Stop driver: `sc start dobro`

## Usage

For control driver run DorbroCli.exe in cmd.exe
```Usage: DobroCli.exe <options>
Options:
  -h                        Show this message.
  -l                        Process & Thread Notify Callbacks Address's & FS Minifilters List.
<Process Callbacks>
  -zp                       Zero out Process Notify Callback's Array (Cowboy Mode).
  -dp <index>               Delete Specific Process Notify Callback (Red Team Mode).
  -pp <index>               Patch Specific Process Notify Callback (Threat Actor Mode).
  -rp <index>               Rollback to the original Process Notify Callback (Thoughtful Ninja Mode).
<Threads Callbacks>
  -zt                       Zero out Thread Notify Callback's Array (Cowboy Mode).
  -dt <index>               Delete Specific Thread Notify Callback (Red Team Mode).
  -pt <index>               Patch Specific Thread Notify Callback (Threat Actor Mode).
  -rt <index>               Rollback to the original Thread Notify Callback (Thoughtful Ninja Mode).
<Hook Notify Callback>
  -hps <index> <filter>     Hook PS notify routine.
  -ups                      Unhook PS notify routine.
  -hthr <index> <filter>    Hook THR notify routine.
  -uthr                     Unhook THR notify routine.
<FS Minifilters>
  -hm <index>               Hook FS Minifilter.
  -um                       Unhook FS Minifilter.
<Check>
  -chk                      Try AV/EDR for fun ;-) (Inject PS, need admin).
<Driver Debug>
  -dbg_lm                   List modules in Driver DbgPrint.
  -dbg_bsod                 BS0D.```

##Links
Articles covering these issues in detail:
1. http://deniable.org/windows/windows-callbacks ---> https://web.archive.org/web/20200326040826/http://deniable.org/windows/windows-callbacks
2. https://synzack.github.io/Blinding-EDR-On-Windows/
3. https://aviadshamriz.medium.com/part-1-fs-minifilter-hooking-7e743b042a9d     
