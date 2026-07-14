// Seed the raw SMK-37 Pro v12 app.bin entry point before auto-analysis.
// @category SMK37

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class Smk37SeedAnalysis extends GhidraScript {
    private static final long EXPECTED_ENTRY = 0x02000120L;

    @Override
    public void run() throws Exception {
        Address entry = toAddr(EXPECTED_ENTRY);
        if (!currentProgram.getMemory().contains(entry)) {
            throw new IllegalStateException("app.bin is not loaded at 0x02000120");
        }
        currentProgram.getSymbolTable().addExternalEntryPoint(entry);
        disassemble(entry);
        if (getFunctionAt(entry) == null) {
            createFunction(entry, "smk37_entry");
        }
        println("SMK37 analysis seed: " + entry);
    }
}
