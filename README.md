<p align="center"><img src="image.png"></p>
<p align="center">
  <img src="https://img.shields.io/github/license/kkent030315/NtSymbol?style=for-the-badge">
  <img src="https://img.shields.io/github/last-commit/kkent030315/NtSymbol?style=for-the-badge">
  <img src="https://img.shields.io/codefactor/grade/github/kkent030315/NtSymbol?style=for-the-badge">
</p>

# NtSymbol

Resolve DOS MZ executable symbols at runtime

# Example

You no longer have not have to use memory pattern scan inside your sneaky rootkit. Pass the RVAs into your kernel payloads!

```cpp
int main()
{
    ntsymbol ntoskrnl("%SYSTEMROOT%\\system32\\ntoskrnl.exe");
    ntoskrnl.init();
    /* Useful for retriving NTOS image base without any calls */
    const auto RvaPsNtosImageBase = ntoskrnl.resolve(L"PsNtosImageBase");
    
    
    ntsymbol cidll("%SYSTEMROOT%\\system32\\CI.dll");
    cidll.init();
    /* DSE Bypass! */
    const auto RvaCiOptions = cidll.resolve(L"g_CiOptions");
}
```
