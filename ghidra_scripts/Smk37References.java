// Report references to one or more addresses.
// @category SMK37

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class Smk37References extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "usage: Smk37References.java output.txt address...");
        }
        StringBuilder report = new StringBuilder();
        for (int index = 1; index < args.length; index++) {
            Address target = toAddr(Long.decode(args[index]));
            report.append("target=").append(target).append('\n');
            Reference[] references = getReferencesTo(target);
            int count = 0;
            for (Reference reference : references) {
                Address from = reference.getFromAddress();
                Instruction instruction = getInstructionContaining(from);
                Function function = getFunctionContaining(from);
                report.append("  from=").append(from)
                      .append(" type=").append(reference.getReferenceType());
                if (instruction != null) {
                    report.append(" instruction=").append(instruction);
                }
                if (function != null) {
                    report.append(" function=").append(function.getName())
                          .append('@').append(function.getEntryPoint());
                }
                report.append('\n');
                count++;
            }
            report.append("count=").append(count).append("\n\n");
        }
        Path output = Path.of(args[0]);
        Files.createDirectories(output.toAbsolutePath().getParent());
        Files.writeString(output, report.toString(), StandardCharsets.UTF_8);
        println("SMK37 reference report written: " + output);
    }
}
