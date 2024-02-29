// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <CLI/CLI.hpp>
#include <charconv>
#include <cstdlib>
#include <cxxabi.h>
#include <fstream>
#include <iostream>
#include <malloc/_malloc.h>
#include <nlohmann/json.hpp>
#include <rego/rego.hh>
#include <sstream>
#include <string>

namespace
{
	/**
	 * Add the board JSON to a Rego interpreter.  The board files are *almost*
	 * JSON, with the exception that they use 0x for hex numbers.  This
	 * function will try parsing the board description and rewrite the hex
	 * numbers to decimal when it encounters them.
	 */
	bool add_board_json(rego::Interpreter &rego, std::string_view filename)
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
		const std::string_view ExportPrefix = "__export_";
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
		if (!string.starts_with("_"))
		{
			return scalar(false);
		}
		string            = string.substr(1);
		size_t bufferSize = 128;
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

	Node decode_c_string(const Nodes &args)
	{
		auto bytes =
		  decode_hex_node(unwrap_arg(args, UnwrapOpt(0).types({JSONString})));
		auto        offsetNode = unwrap_arg(args, UnwrapOpt(1).types({Int}));
		size_t      offset     = get_int(offsetNode).to_int();
		std::string result;
		if ((offset < 0) || (offset >= bytes.size()))
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
	rego.add_module("compartment", R"(
		package compartment

		compartment_contains_export(compartment, export) {
			compartment.exports[_] == export
		}

		files_for_export(export) = f {
			some compartments
			compartments = [compartment | compartment = input.compartments[_]; compartment_contains_export(compartment, export)]
			# FIXME: Look in data sections as well
			f = {f2 | compartments[_].code.inputs[_].file = f2}
		}

		export_matches_import(export, importEntry)  {
			export.export_symbol = importEntry.export_symbol
		}


		export_for_import(importEntry) = entry { 
			some possibleEntries
			some allExports
			allExports = {export | input.compartments[_].exports[_] = export}
			possibleEntries = [entry | entry = allExports[_]; export_matches_import(entry, importEntry)]
			count(possibleEntries) == 1
			files_for_export(possibleEntries[0])[_] == importEntry.provided_by
			entry := possibleEntries[0]
		}

		import_is_library_call(a) { a.kind = "LibraryFunction" }
		import_is_MMIO(a) { a.kind = "MMIO" }
		import_is_compartment_call(a) {
			a.kind = "CompartmentExport"
			a.function
		}

		mmio_imports_for_compartment(compartment) = entry {
			entry := [e | e = compartment.imports[_]; import_is_MMIO(e)]
		}

		mmio_is_device(importEntry, device) {
			importEntry.start = device.start
			importEntry.length = device.length
		}

		device_for_mmio_import(importEntry) = device {
			import_is_MMIO(importEntry)
			some devices
			devices = [{ i:d } | d = data.board.devices[i]; mmio_is_device(importEntry, d)]
			count(devices) == 1
			device := devices[0]
		}

		compartment_imports_device(compartment, device) {
			count([d | d = mmio_imports_for_compartment(compartment)[_] ; mmio_is_device(d, device)]) > 0
		}

		compartments_with_mmio_import(device) = compartments {
			compartments = [i | c = input.compartments[i]; compartment_imports_device(c, device)]
		}

		compartment_export_matching_symbol(compartmentName, symbol) = export {
			some compartment
			compartment = input.compartments[compartmentName]
			some exports
			exports = [e | e = compartment.exports[_]; re_match(symbol, export_entry_demangle(compartmentName, e.export_symbol))]
			count(exports) == 1
			export := exports[0]
		}

		compartments_calling_export(export) = compartments {
			compartments = [c | i = input.compartments[c].imports[_]; export_matches_import(i, export)]
		}

		compartments_calling_export_matching(compartmentName, export) = compartments {
			compartments = compartments_calling_export(compartment_export_matching_symbol(compartmentName, export))
		}

		# Helper for allow lists.  Functions cannot return sets, so this
		# accepts an array of compartment names that match some property and
		# evaluates to true if and only if each one is also present in the allow
		# list.
		allow_list(testArray, allowList) {
			some compartments
			compartments = {c | c:=testArray[_]}
			compartments & allowList == compartments
		}

		mmio_allow_list(mmioName, allowList) {
			allow_list(compartments_with_mmio_import(data.board.devices[mmioName]), allowList)
		}

		compartment_call_allow_list(compartmentName, exportPattern, allowList) {
			allow_list(compartments_calling_export_matching(compartmentName, exportPattern), allowList)
		}


		)");
	rego.add_module("rtos", R"(
		package rtos
		
		import future.keywords

		is_allocator_capability(capability) {
			capability.kind == "SealedObject"
			capability.sealing_type.compartment == "alloc"
			capability.sealing_type.key == "MallocKey"
		}

		decode_allocator_capability(capability) = decoded {
			is_allocator_capability(capability)
			some quota
			quota = integer_from_hex_string(capability.contents, 0, 4)
			# Remaining words are all zero
			integer_from_hex_string(capability.contents, 4, 4) == 0
			integer_from_hex_string(capability.contents, 8, 4) == 0
			integer_from_hex_string(capability.contents, 12, 4) == 0
			integer_from_hex_string(capability.contents, 16, 4) == 0
			integer_from_hex_string(capability.contents, 20, 4) == 0
			decoded := { "quota": quota }
		}

		all_sealed_allocator_capabilities_are_valid {
			some allocatorCapabilities
			allocatorCapabilities = [ c | c = input.compartments[_].imports[_] ; is_allocator_capability(c) ]
			every c in allocatorCapabilities {
				decode_allocator_capability(c)
			}
		}


		valid {
			all_sealed_allocator_capabilities_are_valid
			# Only the allocator may access the revoker.
			data.compartment.mmio_allow_list("revoker", {"allocator"})
			# Only the scheduler may access the interrupt controllers.
			data.compartment.mmio_allow_list("clint", {"scheduler"})
			data.compartment.mmio_allow_list("plic", {"scheduler"})
		}
		)");
	for (auto &modulePath : modules)
	{
		rego.add_module_file(modulePath);
	}
	std::cout << rego.query(query) << std::endl;
}
