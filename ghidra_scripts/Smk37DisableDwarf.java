// The early Pi32v2 module has no Ghidra DWARF register mapping. Keep ELF
// symbols, but disable only the DWARF analyzer to avoid repeated stack-frame
// mapping failures.
// @category SMK37

import ghidra.app.script.GhidraScript;

public class Smk37DisableDwarf extends GhidraScript {
    @Override
    public void run() throws Exception {
        setAnalysisOption(currentProgram, "DWARF", "false");
        println("SMK37 analysis option: DWARF=false");
    }
}
