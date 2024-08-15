CHERIoT Audit
=============

**WARNING**: This should be considered alpha-level software.
The built-in functions and policies are under active development and may change significantly before a v1 release.

When you link a CHERIoT firmware image, one of the outputs is report that describes the relationship between compartments in the firmware.
This includes, among other things:

 - For every code or data section, what is the pre- and post-linking hash?
 - For every thread:
    - How big is its stack?
    - How big is its trusted stack?
    - Where does it start running?
 - For every library or compartment:
    - What entry points does it expose, where are they, and do they run with interrupts disabled?
    - What entry points in other compartments does it call?
    - What sealing types does it expose?
    - What static sealed objects does it include (what is their contents and what type are they sealed with)?

This JSON document is very large, often larger than the linked firmware image.
It can be processed by anything that can consume JSON (i.e. pretty much any programming language, including [COBOL](https://developer.ibm.com/tutorials/parse-json-using-ibm-enterprise-cobol/)).
Most users are likely to want to write a policy for driving code signing or deployment and so a *policy language* is more useful than a general-purpose programming language.

The Open Policy Agent project's [Rego language](https://www.openpolicyagent.org/docs/latest/policy-language) is such a language.
It contains a mixture of declarative and imperative constructs that combine to make writing policies relatively easy.

Building
--------

This project uses a CMake build system and so can be built with the following steps:

```
$ mkdir Build
$ cd Build
$ cmake .. 
$ cmake --build.
```

30-second Rego primer
---------------------

Rego's abstract model is comprised of three layers:

 - An input document (in our case, this is the firmware) and optionally some other documents (for us, this includes the board description, which lets you map from memory ranges to device names).
 - A set of 'virtual documents'.
   These are expressed as modules that consume the inputs and provide views that convey easier to interpret semantics.
   We provide some of these for the core compartmentalisation abstractions and for the RTOS.
   Other subsystems can add their own and you can provide one that encapsulates a policy for your firmware.
 - A query, which is evaluated over the combination of documents and virtual documents and provides some output.
   Typically, for code signing or compliance decisions, this will boil down to whether a complex predicate in one of the virtual documents evaluates to true.

Rego syntax is rich, please consult the official documentation.

Usage
-----

The `cheriot-audit` tool requires a board description file, the firmware report JSON, and a query and can optionally be provided with an arbitrary number of other Rego modules.

```
Audit a CHERIoT firmware image
Usage: cheriot-audit [OPTIONS]

Options:
  -h,--help                   Print this help message and exit
  -b,--board TEXT:FILE REQUIRED
                              Board JSON file
  -m,--module TEXT:FILE ...   Modules to load.  This option may be passed more than once.
  -q,--query TEXT REQUIRED    The query to run.
  -j,--firmware-report TEXT:FILE REQUIRED
                              Firmware report JSON file generated by the linker.
```

You can use this with queries that introspect a firmware image.
For example, if you wanted to see which compartments in the test suite can allocate memory, you might use this query:

```sh
$ cheriot-audit  --board path/to/cheriot-rtos/sdk/boards/sail.json i\
  -j /path/to/cheriot-rtos/tests/build/cheriot/cheriot/release/test-suite.json \
  -q '[ { "owner": owner, "capability": data.rtos.decode_allocator_capability(c) } | c = input.compartments[owner].imports[_] ; data.rtos.is_allocator_capability(c) ]'
[{"capability":{"quota":1024}, "owner":"allocator_test"}, {"capability":{"quota":1048576}, "owner":"allocator_test"}, {"capability":{"quota":4096}, "owner":"eventgroup_test"}, {"capability":{"quota":4096}, "owner":"locks_test"}, {"capability":{"quota":4096}, "owner":"multiwaiter_test"}, {"capability":{"quota":4096}, "owner":"queue_test"}, {"capability":{"quota":4096}, "owner":"thread_pool_test"}]
```

This uses a [Rego comprehension](https://www.openpolicyagent.org/docs/latest/policy-language/#comprehensions) to build an array of objects.
The comprehension contains three parts.
The first defines that the result for each element in the array should be an object with `owner` and `capability` fields whose are defined by the rest of the query.
This uses a function from the `rtos` module to take the raw hex dump from the input report and turn it into structured data.
The second expression defines the things to match, using symbolic values.
This defines a `c` that is a compartment import, selected from any import in any compartment.
Note that this uses Prolog-like unification and so this is all possible pairs of `c` and `owner`, for all compartments and all imports of those compartments.
The third part is the predicate that filters the array.
Only pairs of `owner` and `c` where `c` is an allocator capability are found.

The output of this is a JSON array (and so can be passed into other tools or pretty-printed with [jq](https://github.com/jqlang/jq))
You can see that the `allocator_test` compartment holds two allocator capabilities, allowing up to 1 KiB and 1 MiB of allocations, respectively.
Several other compartments also hold allocator capabilities that allow allocating up to 4 KiB.
This kind of query can be useful during development.


For driving code-signing decisions, you are most likely to want a query that resolves to a simple boolean.
For example, this checks the build-in policy for the RTOS:

```
$ cheriot-audit  --board path/to/cheriot-rtos/sdk/boards/sail.json i\
  -j /path/to/cheriot-rtos/tests/build/cheriot/cheriot/release/test-suite.json \
  -q 'data.rtos.valid'
true
```

This includes checks that the interrupt controller is accessible only by the scheduler, that the hardware revoker (if one exists) is exclusive to the allocator, that all allocator capabilities are valid, and a few other things.

Built ins
---------

The tool provides several built-in functions and two built-in modules.
These are experimental and subject to change without notice!

### Built-in functions

`export_entry_demangle(compartmentName, exportSymbol)`

Given the name of a function and the symbol (typically the `export_symbol` field of an import or export table entry), provides the human-friendly name of the exported function.

`integer_from_hex_string(hexString, startOffset, length)`

Given a string from the `contents` field of an export-table entry describing a static sealed object, extract an integer that is `length` bytes log and starts `offset` bytes into the object.
This reads the bytes in the device's byte order and works for 1, 2, and 4-byte quantities.
Evaluates to false in failure conditions.

`string_from_hex_string(hexString, startOffset)`

Given a hex string from the `contents` field of an export-table entry describing a static sealed object, extract a C string starting `startOffset` bytes in.

### The compartment package

The built-in `compartment` package (accessed via the `data.compartment` prefix) contains helpers related to the compartment model.

`export_for_import(importEntry)`

Given an entry from a compartment's `imports` array, returns the corresponding `export` entry.

`import_is_library_call(a)`
`import_is_compartment_call(a)`
`import_is_MMIO(a)`

Type predicates that, given an entry from a compartment's `imports` array, hold if the import refers to a cross-compartment call, a cross-library call, or an MMIO capability.

`import_is_callable(a)`

Type predicate that, given an entry from a compartment's `imports` array, holds if the import refers to either a compartment or library call.

`mmio_imports_for_compartment(compartment)`

Helper that returns all of the MMIO imports for a compartment.

`mmio_is_device(importEntry, device)`

Predicate that, given an entry from a compartment's `imports` array and a device description from the board JSON file, holds if they match.

`device_for_mmio_import(importEntry)`

Given an entry from a compartment's `imports` array, if it refers to a device from the board description, return the device.

`compartment_imports_device(compartment, device)`

Predicate that holds if `compartment` is a compartment from the compartment report that imports `device` from the board description.

`compartments_with_mmio_import(device)`

Returns an array of all of the compartments that import a specific device.


`compartment_export_matching_symbol(compartmentName, symbol)`

Given a compartment and a regular expression describing a (unique) demangled function name from that compartment, return the export entry.

`compartments_calling_export(export)`

Returns an array of all compartments that can directly call a specific export table entry from another compartment or library.

`compartments_calling_export_matching(compartmentName, export)`

Given a compartment name and a regular expression (uniquely) describing an exported function, return the array of compartments that may directly call that function.

`compartment_exports_function(callee, importEntry)`

Predicate that matches if the compartment (or library) named by `callee` is the compartment that exports the entry point given by `importEntry`.

`compartments_calling(callee)`

Returns the names of all compartments that call the compartment named by `callee` (via any exported function).

`allow_list(testArray, allowSet)`

Helper for allow lists.
Functions cannot return sets, so this accepts an array of compartment names that match some property and evaluates to true if and only if each one is also present in the allow list.

`mmio_allow_list(mmioName, allowSet)`

Predicate that, given the name of a device and a set of compartments that are allowed to access it, fails if any other compartment has access to the device.

`compartment_call_allow_list(compartmentName, exportPattern, allowSet)`

Predicate that, given the name of a compartment and a regular expression that uniquely identifies one of its exported functions, fails if any compartment not in the allow set is able to call it.

`compartment_allow_list(compartmentName, allowSet)`

Predicate that, given the name of a compartment, fails if any compartment not in the allow set is able to call any of the exported entry points from this function.

`shared_object_imports_for_compartment(compartment)`

Given a compartment name, return a list of all of the imports of shared objects.

`compartment_imports_shared_object(compartment, object)`

Predicate that evaluates to true if the compartment named `compartment` imports the shared object named with the name given by the second.

`compartment_imports_shared_object_writeable(compartment, object)`

Predicate that evaluates to true if the compartment named `compartment` imports the shared object named with the name given by the second *and* that compartment can write to the shared object.

`compartments_with_shared_object_import(object)`

Given the name of a shared object, evaluates to a list of compartments that import that object.

`compartments_with_shared_object_import_writeable(object)`

Given the name of a shared object, evaluates to a list of compartments that import that object with permissions that allow writing.

`shared_object_allow_list(objectName, allowList)`

Predicate that, given the name of a shared object and a set of compartments that are allowed to access it, fails if any other compartment has access to the global.

`shared_object_writeable_allow_list(objectName, allowList)`

Predicate that, given the name of a shared object and a set of compartments that are allowed to access it, fails if any other compartment has write access to the global.

### The RTOS package

The built-in `rtos` package (accessed via the `data.rtos` prefix) contains helpers related to the compartment model.

`is_allocator_capability(capability)`

Predicate that holds if given an export entry that is a sealed object that is called with allocator's sealing key.
Note that this does *not* validate the contents of the sealed object.

`decode_allocator_capability(capability)`

Given a static sealed object, decodes it as an allocator capability.
This also serves as a predicate that this is a *valid* allocator capability and will fail if this is not a valid allocator capability.

`all_sealed_allocator_capabilities_are_valid`

Rule that holds if all sealed objects that are sealed with the allocator's capability are valid.

`valid`

Rule that holds if the RTOS state is as expected.
Note: This is currently (very) incomplete.
