// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

namespace
{
	auto compartmentPackage = R"(
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
		)";
} // namespace
