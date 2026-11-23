// Ghidra headless post-script: writes the image base, then every function's
// entry (in memory, not external), in hex, one per line, to the file named
// by the first script argument.
//@category binbun

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;

public class ListFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        try (PrintWriter out = new PrintWriter(getScriptArgs()[0])) {
            out.println(Long.toHexString(currentProgram.getImageBase().getOffset()));
            for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
                if (!function.isExternal()) {
                    out.println(Long.toHexString(function.getEntryPoint().getOffset()));
                }
            }
        }
    }
}
