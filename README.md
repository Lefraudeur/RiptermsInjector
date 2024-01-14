# RiptermsInjector

Reflective pe file loader for x64 windows, or whatever it's called

Has some useless code because I was experimenting things

It does not use CreateRemoteThread to call dll entry point and instead replaces the import address of HeapAlloc in msvcrt.dll by the dll's entrypoint.
</br>So its like hooking HeapAlloc, meaning if the target process doesn't call HeapAlloc, the dll will never be injected...
</br>(I know this is dumb, but it was for scientific purposes ok)

### Usage:
By default, it injects https://github.com/Lefraudeur/RiptermsGhost in Lunar Client.
</br>To inject your own dll, replace the file dll/dll.dll by your own dll and run File2Hex.exe.
</br>Make sure to replace target process's window name in main.cpp as well
