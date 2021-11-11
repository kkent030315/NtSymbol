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

#pragma once
#include <windows.h>
#include <string>
#include <filesystem>

#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

#pragma comment(lib, "rpcrt4.lib") // UuidToStringA, RpcStringFreeA
#pragma comment(lib, "urlmon.lib") // UrlDownloadToFileA

class pe_blob
{
public:
	pe_blob(const std::string& path);
	~pe_blob();
	bool valid();
	template<typename T> T as() noexcept { return reinterpret_cast<T>(this->blob); }
private:
	void* blob;
};

class ntsymbol
{
	struct pe_debug_info
	{
		GUID guid;
		uint32_t age;
		std::string image_name;
	};

	struct IMAGE_DEBUG_DIRECTORY_RAW
	{
		char format[4];
		char guid[16];
		unsigned long age;
		char image_name[256];
	};

public:
	ntsymbol(const std::string& image_path);
	~ntsymbol();
	bool init();

	template<typename C>
	bool enum_symbol(
		const std::wstring& root_name, const C&& callback, void* context = nullptr)
	{
		SYMBOL_INFOW symbol_info = { 0 };
		if (!SymGetTypeFromNameW(this->process, this->base, root_name.data(), &symbol_info))
			return true;

		ULONG child_count;
		if (!SymGetTypeInfo(this->process, this->base, symbol_info.TypeIndex, TI_GET_CHILDRENCOUNT, &child_count))
			return true;

		const auto alloc_size = child_count * sizeof(ULONG) + sizeof(TI_FINDCHILDREN_PARAMS);
		const auto children = reinterpret_cast<TI_FINDCHILDREN_PARAMS*>(VirtualAlloc(NULL, alloc_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
		if (!children)
			return true;

		RtlZeroMemory(children, alloc_size);
		children->Count = child_count;
		children->Start = 0;

		if (!SymGetTypeInfo(this->process, this->base, symbol_info.TypeIndex, TI_FINDCHILDREN, children))
		{
			VirtualFree(reinterpret_cast<LPVOID>(children), 0, MEM_RELEASE);
			return true;
		}

		for (ULONG i = children->Start; i < children->Count; i++)
		{
			if (!callback(children->ChildId[i], context))
			{
				VirtualFree(reinterpret_cast<LPVOID>(children), 0, MEM_RELEASE);
				return false;
			}
		}

		VirtualFree(reinterpret_cast<LPVOID>(children), 0, MEM_RELEASE);
		return true;
	}

	uint64_t resolve(const std::wstring& name);
	uint64_t resolve(const std::wstring& struct_name, const std::wstring& member_name);

private:
	pe_debug_info get_debug_info();
	std::string get_msdl_link();
	std::string guid2str(GUID guid);
	bool download_symbol();

	std::string image_path;
	std::string symbol_server;
	std::string symbol_path;
	HANDLE process;
	uint64_t base;
};

