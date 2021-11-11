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

#include "ntsymbol.hpp"

ntsymbol::ntsymbol(const std::string& image_path)
	: symbol_server("http://msdl.microsoft.com/download/symbols/")
	, process(GetCurrentProcess())
{
	char buffer[MAX_PATH];
	GetCurrentDirectoryA(MAX_PATH, buffer);
	this->symbol_path = std::string(buffer) + "\\";

	if (ExpandEnvironmentStringsA(image_path.c_str(), buffer, MAX_PATH))
		this->image_path = buffer;
	else
		this->image_path = image_path;
}

ntsymbol::~ntsymbol()
{
	SymCleanup(this->process);
}

ntsymbol::pe_debug_info ntsymbol::get_debug_info()
{
	/*
	* NOTE:
	* SymSrvGetFileIndexInfo is not supported in
	* WinXP & Win2k3 versions of dbghelp.dll
	* See more on https://bugzilla.mozilla.org/show_bug.cgi?id=712109
	*/

	pe_blob lib(this->image_path);
	if (!lib.valid())
		return {};

	const auto nt_headers = ImageNtHeader(lib.as<void*>());
	const auto debug_dir =
		reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(
			lib.as<uint8_t*>() +
			nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);

	if (debug_dir->Type != IMAGE_DEBUG_TYPE_CODEVIEW)
		return {};

	auto debug_info = reinterpret_cast<IMAGE_DEBUG_DIRECTORY_RAW*>(
		lib.as<uint8_t*>() + debug_dir->AddressOfRawData);

	ntsymbol::pe_debug_info info{};
	info.guid = *reinterpret_cast<GUID*>(debug_info->guid);
	info.age = debug_info->age;
	info.image_name = debug_info->image_name;

	return info;
}

std::string ntsymbol::get_msdl_link()
{
	const auto replace_string = [](std::string s1, std::string s2, std::string s3) -> auto
	{
		std::string::size_type  pos(s1.find(s2));

		while (pos != std::string::npos)
		{
			s1.replace(pos, s2.length(), s3);
			pos = s1.find(s2, pos + s3.length());
		}

		return s1;
	};

	const auto debug_info = this->get_debug_info();
	if (debug_info.image_name.empty())
		return {};

	char buf[MAX_PATH];
	sprintf_s(buf, "%d", debug_info.age);

	const auto guid_str = this->guid2str(debug_info.guid);
	const auto repl = replace_string(guid_str, "-", "");
	return
		std::string(
			"http://msdl.microsoft.com/download/symbols/" +
			debug_info.image_name + "/" + repl + buf + "/" +
			debug_info.image_name);
}

std::string ntsymbol::guid2str(GUID guid)
{
	std::string guid_str;
	RPC_CSTR rpc_str;

	if (UuidToStringA(reinterpret_cast<const UUID*>(&guid), &rpc_str) == RPC_S_OK)
	{
		guid_str = reinterpret_cast<char*>(rpc_str);
		RpcStringFreeA(&rpc_str);
	}

	return guid_str;
}

bool ntsymbol::download_symbol()
{
	const auto debug_info = this->get_debug_info();
	const auto filename = debug_info.image_name;
	if (filename.empty())
		return false;

	const auto link = this->get_msdl_link();
	if (link.empty())
		return false;

	const auto full_path = this->symbol_path + filename;
	if (std::filesystem::exists(full_path))
		return true;

	return SUCCEEDED(URLDownloadToFileA(nullptr, link.c_str(), full_path.c_str(), 0, nullptr));
}

bool ntsymbol::init()
{
	if (!std::filesystem::exists(this->symbol_path))
		return false;

	if (!this->download_symbol())
		return false;

	if (!SymInitialize(this->process, nullptr, FALSE))
		return false;

	if (!(this->base =
		SymLoadModuleEx(
			this->process, nullptr, this->image_path.c_str(), nullptr, 0, 0, nullptr, 0)))
		return false;

	return true;
}

uint64_t ntsymbol::resolve(const std::wstring& name)
{
	SYMBOL_INFOW symbol_info = { 0 };

	if (!SymGetTypeFromNameW(this->process, this->base, name.data(), &symbol_info))
		return 0;

	ULONG offset;
	if (!SymGetTypeInfo(this->process, this->base, symbol_info.Index, TI_GET_ADDRESSOFFSET, &offset))
		return 0;

	return static_cast<uint64_t>(offset);
}

uint64_t ntsymbol::resolve(const std::wstring& struct_name, const std::wstring& member_name)
{
	ULONG offset = 0;

	this->enum_symbol(struct_name, [&](ULONG child_id, void*)
		{
			LPCWSTR name;
			if (SymGetTypeInfo(this->process, this->base, child_id, TI_GET_SYMNAME, &name))
			{
				if (!_wcsicmp(member_name.data(), name))
				{
					if (SymGetTypeInfo(this->process, this->base, child_id, TI_GET_OFFSET, &offset))
					{
						VirtualFree((LPVOID)name, 0, MEM_RELEASE);
						return false;
					}
				}

				VirtualFree((LPVOID)name, 0, MEM_RELEASE);
			}

			return true;
		});

	return static_cast<uint64_t>(offset);
}

pe_blob::pe_blob(const std::string& path) : blob(LoadLibraryExA(path.data(), NULL, DONT_RESOLVE_DLL_REFERENCES))
{
}

pe_blob::~pe_blob()
{
	if (this->blob)
		FreeLibrary(reinterpret_cast<HMODULE>(this->blob));
}

bool pe_blob::valid()
{
	return !!this->blob;
}
