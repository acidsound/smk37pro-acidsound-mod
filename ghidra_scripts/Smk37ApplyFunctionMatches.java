// Apply high-confidence exact SDK function-body matches before auto-analysis.
// Input format: address<TAB>name, one per line.
// @category SMK37

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class Smk37ApplyFunctionMatches extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException(
                "usage: Smk37ApplyFunctionMatches.java seeds.tsv");
        }
        List<String> lines = Files.readAllLines(Path.of(args[0]), StandardCharsets.UTF_8);
        int applied = 0;
        for (String line : lines) {
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }
            String[] fields = line.split("\\t", 2);
            if (fields.length != 2) {
                throw new IllegalArgumentException("invalid seed line: " + line);
            }
            long value = Long.decode(fields[0]);
            Address address = toAddr(value);
            if (!currentProgram.getMemory().contains(address)) {
                throw new IllegalArgumentException("seed outside app.bin: " + line);
            }
            String name = fields[1].replaceAll("[^A-Za-z0-9_$]", "_");
            disassemble(address);
            Function function = getFunctionAt(address);
            if (function == null) {
                function = createFunction(address, name);
            }
            if (function != null && function.getName().startsWith("FUN_")) {
                function.setName(name, SourceType.IMPORTED);
            }
            applied++;
        }
        println("SMK37 exact function seeds applied: " + applied);
    }
}
