// Ghidra headless post-script: decompiles every function as Ghidra's
// File > Export Program > C/C++ does (CppExporter: its decompiler options,
// its parallel decompiler, its default timeout, the same text), but writes
// each function apart, under the directory named by the first script
// argument:
//
// - header.h: what CppExporter's header holds: the fake C types for the
//   decompiler's own type names, the program's data types (DataTypeWriter)
//   and every decompiled function's prototype;
// - functions.c: each function after a line `//@bench ADDRESS`, then a
//   line per global variable it references (`//@global DECLARATION`), then
//   its C; a function Ghidra cannot decompile has `//@failed REASON`
//   instead;
// - names.txt: the image base, then every primary symbol in memory,
//   `address name` in hex, one per line;
// - version.txt: Ghidra's version.
//@category binbun

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.exporter.CppExporter;
import ghidra.framework.Application;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypeWriter;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class DecompileAll extends GhidraScript {

    private record Result(long address, String signature, String body, List<String> globals,
            String failure) {}

    @Override
    public void run() throws Exception {
        File out = new File(getScriptArgs()[0]);
        out.mkdirs();
        long base = currentProgram.getImageBase().getOffset();
        try (PrintWriter version = new PrintWriter(new File(out, "version.txt"))) {
            version.println(Application.getApplicationVersion());
        }

        DecompileOptions options = DecompilerUtils.getDecompileOptions(null, currentProgram);
        DecompilerCallback<Result> callback =
            new DecompilerCallback<>(currentProgram, decompiler -> {
                decompiler.setOptions(options);
                decompiler.toggleSyntaxTree(true);
            }) {
                @Override
                public Result process(DecompileResults results, TaskMonitor monitor) {
                    Function function = results.getFunction();
                    long address = function.getEntryPoint().getOffset() - base;
                    String error = results.getErrorMessage();
                    if (!results.decompileCompleted() || (error != null && !error.isEmpty())) {
                        return new Result(address, null, null, List.of(),
                            error == null || error.isEmpty() ? "not completed"
                                    : error.replace('\n', ' '));
                    }
                    DecompiledFunction decompiled = results.getDecompiledFunction();
                    List<String> globals = new ArrayList<>();
                    Iterator<HighSymbol> symbols =
                        results.getHighFunction().getGlobalSymbolMap().getSymbols();
                    while (symbols.hasNext()) {
                        HighSymbol symbol = symbols.next();
                        String type = symbol.getDataType().getDisplayName();
                        String space = type.endsWith("*") ? "" : " ";
                        globals.add(type + space + symbol.getName() + ";");
                    }
                    return new Result(address, decompiled.getSignature(), decompiled.getC(),
                        globals, null);
                }
            };
        callback.setTimeout(options.getDefaultTimeout());
        List<Function> functions = new ArrayList<>();
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (!function.isExternal()) {
                functions.add(function);
            }
        }
        List<Result> results =
            ParallelDecompiler.decompileFunctions(callback, functions, monitor);
        callback.dispose();
        results.sort((a, b) -> Long.compareUnsigned(a.address(), b.address()));

        DataTypeManager types = currentProgram.getDataTypeManager();
        try (PrintWriter header = new PrintWriter(new File(out, "header.h"))) {
            // CppExporter's own definitions of the decompiler's fake types.
            Method fake = CppExporter.class.getDeclaredMethod("getFakeCTypeDefinitions",
                DataOrganization.class);
            fake.setAccessible(true);
            header.write((String) fake.invoke(null, types.getDataOrganization()));
            StringWriter written = new StringWriter();
            new DataTypeWriter(types, written, false).write(types, monitor);
            header.write(written.toString());
            header.println();
            for (Result result : results) {
                if (result != null && result.signature() != null) {
                    header.println(result.signature());
                }
            }
        }
        try (PrintWriter c = new PrintWriter(new File(out, "functions.c"))) {
            for (Result result : results) {
                if (result == null) {
                    continue;
                }
                c.println("//@bench " + Long.toHexString(result.address()));
                if (result.failure() != null) {
                    c.println("//@failed " + result.failure());
                    continue;
                }
                for (String global : result.globals()) {
                    c.println("//@global " + global);
                }
                c.println(result.body());
            }
        }
        try (PrintWriter names = new PrintWriter(new File(out, "names.txt"))) {
            names.println("=");
            SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
            while (symbols.hasNext()) {
                Symbol symbol = symbols.next();
                if (symbol.isPrimary() && symbol.getAddress().isMemoryAddress()) {
                    names.println(Long.toHexString(symbol.getAddress().getOffset() - base) + " "
                        + symbol.getName());
                }
            }
        }
    }
}
