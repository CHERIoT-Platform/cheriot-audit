// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <CLI/CLI.hpp>
#include <charconv>
#include <cxxabi.h>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <rego/rego.hh>
#include <sstream>
#include <string>

#include "compartment.hh"
#include "rtos.hh"

namespace
{
	/**
	 * Add the board JSON to a Rego interpreter.  The board files are *almost*
	 * JSON, with the exception that they use 0x for hex numbers.  This
	 * function will try parsing the board description and rewrite the hex
	 * numbers to decimal when it encounters them.
	 */
	bool add_board_json(rego::Interpreter &rego, const std::string &filename)
	{
		nlohmann::json j;
		std::ifstream  ifs(filename);
		std::string    value(std::istreambuf_iterator<char>{ifs}, {});
		while (j.empty())
		{
			try
			{
				j = j.parse(value);
				break;
			}
			catch (nlohmann::json::parse_error &e)
			{
				if (e.byte < 2)
				{
					return false;
				}
				if (value.substr(e.byte - 2, 2) != "0x")
				{
					return false;
				}
				uint32_t    result;
				const char *start = value.c_str() + e.byte;
				auto [end, error] = std::from_chars(
				  start, value.c_str() + value.size(), result, 16);
				if (error != std::errc{})
				{
					return false;
				}
				std::stringstream ss;
				ss.setf(std::ios::dec);
				ss << result;
				start -= 2;
				value.replace(start - value.c_str(), end - start, ss.str());
				start = value.c_str() + (e.byte - 2);
			}
		}
		// Now that we've parsed the JSON, normalise it slightly.  Devices can
		// be expressed as start and end or start and length.  In the linker
		// report, they're always start and length, so we'll convert any end to
		// a length.
		for (auto &device : j["devices"])
		{
			if (device.contains("end"))
			{
				device["length"] = device["end"].get<uint32_t>() -
				                   device["start"].get<uint32_t>();
				device.erase("end");
			}
		}
		std::stringstream ss;
		ss << "{ \"board\": " << j.dump() << "}";
		rego.add_data_json(ss.str());
		return true;
	}

	using namespace rego;

	/**
	 * Built-in function exposed to Rego for demangling the symbol names in
	 * export entries.  Takes two arguments, the compartment name and the
	 * mangled symbol name.
	 */
	Node demangle_export(const Nodes &args)
	{
		Node exportName = unwrap_arg(args, UnwrapOpt(1).types({JSONString}));
		if (exportName->type() == Error)
		{
			return scalar(false);
		}
		Node compartmentName =
		  unwrap_arg(args, UnwrapOpt(0).types({JSONString}));
		if (compartmentName->type() == Error)
		{
			return scalar(false);
		}
		auto string                         = get_string(exportName);
		auto compartmentNameString          = get_string(compartmentName);
		const std::string_view LibraryExportPrefix = "__library_export_libcalls";
		const std::string_view ExportPrefix = "__export_";
		if (string.starts_with(LibraryExportPrefix))
		{
			string = string.substr(LibraryExportPrefix.size());
		}
		else
		{
			if (!string.starts_with(ExportPrefix))
			{
				return scalar(false);
			}
			string = string.substr(ExportPrefix.size());
			if (!string.starts_with(compartmentNameString))
			{
				return scalar(false);
			}
			string = string.substr(compartmentNameString.size());
		}
		if (!string.starts_with("_"))
		{
			return scalar(false);
		}
		string            = string.substr(1);
		// The way that rego-cpp exposes snmalloc can cause the realloc here to
		// crash.  Try to allocate a buffer that's large enough that we don't
		// care.
		size_t bufferSize = strlen(string.c_str()) * 8;
		char  *buffer     = static_cast<char *>(malloc(bufferSize));
		int    error;
		buffer =
		  abi::__cxa_demangle(string.c_str(), buffer, &bufferSize, &error);
		if (error != 0)
		{
			free(buffer);
			return scalar(false);
		}
		std::string demangled(buffer);
		free(buffer);
		return scalar(std::move(demangled));
	}

	/**
	 * Helper that decodes the hex strings emitted for static sealed objects.
	 * These are written as sequences of bytes, with a space between each four
	 * bytes.
	 *
	 * Takes a node that must have been unwrapped to a JSONString.
	 */
	std::vector<uint8_t> decode_hex_node(const Node &node)
	{
		if (node->type() == Error)
		{
			return {};
		}
		auto                 hexString = get_string(node);
		std::vector<uint8_t> result;
		while (hexString.size() >= 8)
		{
			for (size_t i = 0; i < 8; i += 2)
			{
				uint8_t byte;
				auto [p, ec] = std::from_chars(
				  hexString.data() + i, hexString.data() + i + 2, byte, 16);
				if (ec != std::errc{})
				{
					return {};
				}
				result.push_back(byte);
			}
			hexString = hexString.substr(8);
			if (hexString.size() > 0 && hexString[0] == ' ')
			{
				hexString = hexString.substr(1);
			}
		}
		return result;
	}

	/**
	 * Built-in function exposed to Rego for decoding a hex string into an
	 * integer.
	 *
	 * Takes three arguments:
	 * 1. The hex string to decode
	 * 2. The offset in the string to start decoding
	 * 3. The number of bytes to decode
	 *
	 * The third argument must be 1, 2, 3, or 4 bytes (3 does not make sense,
	 * but it's easier to allow it than exclude it).  This corresponds to
	 * uint8_t, uint16_t, and uint32_t in the source.
	 */
	Node decode_integer(const Nodes &args)
	{
		auto bytes =
		  decode_hex_node(unwrap_arg(args, UnwrapOpt(0).types({JSONString})));
		auto offsetNode = unwrap_arg(args, UnwrapOpt(1).types({Int}));
		auto lengthNode = unwrap_arg(args, UnwrapOpt(2).types({Int}));
		if ((offsetNode->type() == Error) || (lengthNode->type() == Error))
		{
			return scalar(false);
		}
		size_t   offset = get_int(offsetNode).to_int();
		size_t   length = get_int(lengthNode).to_int();
		uint32_t result = 0;
		size_t   end    = offset + length;
		if ((length > 4) || (end > bytes.size()))
		{
			return scalar(false);
		}
		for (size_t i = 0; i < length; i++)
		{
			result |= (bytes[offset + i] << (i * 8));
		}
		return scalar(BigInt{int64_t(result)});
	}

	/**
	 * Built-in function exposed to Rego for decoding a hex string containing a
	 * C string into a Rego string.  This takes two arguments, the hex string
	 * and the offset where the C string starts.
	 */
	Node decode_c_string(const Nodes &args)
	{
		auto bytes =
		  decode_hex_node(unwrap_arg(args, UnwrapOpt(0).types({JSONString})));
		auto        offsetNode = unwrap_arg(args, UnwrapOpt(1).types({Int}));
		size_t      offset     = get_int(offsetNode).to_int();
		std::string result;
		if (offset >= bytes.size())
		{
			return scalar(false);
		}
		for (auto it = bytes.begin() + offset;
		     (it != bytes.end()) && (*it != '\0');
		     it++)
		{
			result.push_back(*it);
		}
		return scalar(std::move(result));
	}

	std::string
	extract_first_expression_from_result(const std::string &result_json)
	{
		if (result_json == "undefined")
		{
			return result_json;
		}

		nlohmann::json result;
		try
		{
			result = result.parse(result_json);
		}
		catch (nlohmann::json::parse_error &e)
		{
			return e.what();
		}

		if (result.is_array())
		{
			if (result.empty())
			{
				std::cerr << "warning: query returned no results." << std::endl;
				return result_json;
			}

			if (result.size() > 1)
			{
				std::cerr << "warning: query returned multiple results. Only "
				             "the first will be used."
				          << std::endl;
			}

			result = result[0];
		}

		if (!result.is_object())
		{
			std::cerr
			  << "error: expected results to be either an array or an object."
			  << std::endl;
			return result_json;
		}

		if (!result.contains("expressions"))
		{
			std::cerr << "error: result object does not contain 'expressions'"
			          << std::endl;
			return result_json;
		}

		auto &expressions = result["expressions"];
		if (!expressions.is_array())
		{
			std::cerr << "error: expected 'expressions' to be an array"
			          << std::endl;
			return result_json;
		}

		if (expressions.empty())
		{
			std::cerr << "warning: query returned no results." << std::endl;
			return result_json;
		}

		return expressions[0].dump();
	}
} // namespace

int main(int argc, char **argv)
{
	CLI::App                           app{"Audit a CHERIoT firmware image"};
	std::string                        boardJSONFile;
	std::string                        firmwareReportJSONFile;
	std::vector<std::filesystem::path> modules;
	std::string                        query;
	app.add_option("-b,--board", boardJSONFile, "Board JSON file")
	  ->required()
	  ->check(CLI::ExistingFile);
	app
	  .add_option("-m,--module",
	              modules,
	              "Modules to load.  This option may be passed more than once.")
	  ->check(CLI::ExistingFile);
	app.add_option("-q,--query", query, "The query to run.")->required();
	app
	  .add_option("-j,--firmware-report",
	              firmwareReportJSONFile,
	              "Firmware report JSON file generated by the linker.")
	  ->required()
	  ->check(CLI::ExistingFile);
	CLI11_PARSE(app, argc, argv);
	rego::Interpreter rego;
	rego.builtins().register_builtin(BuiltInDef::create(
	  Location("export_entry_demangle"), 2, demangle_export));
	rego.builtins().register_builtin(BuiltInDef::create(
	  Location("integer_from_hex_string"), 3, decode_integer));
	rego.builtins().register_builtin(BuiltInDef::create(
	  Location("string_from_hex_string"), 2, decode_c_string));
	rego.set_input_json_file(firmwareReportJSONFile);
	if (!add_board_json(rego, boardJSONFile))
	{
		std::cerr << "Failed to parse board JSON" << std::endl;
		return EXIT_FAILURE;
	}
	rego.add_module("compartment", compartmentPackage);
	rego.add_module("rtos", rtosPackage);
	for (auto &modulePath : modules)
	{
		rego.add_module_file(modulePath);
	}
	std::cout << extract_first_expression_from_result(rego.query(query))
	          << std::endl;
}
