/*
 * MIT License
 *
 * Copyright (c) 2021 Kento Oki 
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include <iostream>

#include <ntsymbol.hpp>
#pragma comment(lib, "libNtSymbol.lib")

int main(int argc, const char** argv, const char** envp)
{
    ntsymbol ntoskrnl("%SYSTEMROOT%\\system32\\ntoskrnl.exe");
    if (!ntoskrnl.init())
    {
        printf("[!] failed to init ntoskrnl symbol\n");
        return EXIT_FAILURE;
    }

    printf("[*] *** ntoskrnl.exe ***\n");
    printf("[*]               PsNtosImageBase: 0x%llX\n", ntoskrnl.resolve(L"PsNtosImageBase"));
    printf("[*]             MmUnloadedDrivers: 0x%llX\n", ntoskrnl.resolve(L"MmUnloadedDrivers"));
    printf("[*]                     CmpLogExt: 0x%llX\n", ntoskrnl.resolve(L"CmpLogExt"));
    printf("[*] _EPROCESS::SectionBaseAddress: 0x%llX\n", ntoskrnl.resolve(L"_EPROCESS", L"SectionBaseAddress"));
    printf("[*]     _EPROCESS::RundownProtect: 0x%llX\n", ntoskrnl.resolve(L"_EPROCESS", L"RundownProtect"));
    printf("[*]   _ETHREAD::Win32StartAddress: 0x%llX\n", ntoskrnl.resolve(L"_ETHREAD", L"Win32StartAddress"));
    printf("[*]   _ETHREAD::ChargeOnlySession: 0x%llX\n", ntoskrnl.resolve(L"_ETHREAD", L"ChargeOnlySession"));

    ntsymbol cidll("%SYSTEMROOT%\\system32\\ci.dll");
    if (!cidll.init())
    {
        printf("[!] failed to init CI.dll symbol\n");
        return EXIT_FAILURE;
    }

    printf("[*] *** CI.dll ***\n");
    printf("[*] g_CiOptions: 0x%llX\n", cidll.resolve(L"g_CiOptions"));

    return EXIT_SUCCESS;
}