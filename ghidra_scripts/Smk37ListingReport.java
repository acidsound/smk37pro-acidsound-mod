// Export disassembly for functions whose names start with a supplied prefix.
// @category SMK37

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class Smk37ListingReport extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException(
                "usage: Smk37ListingReport.java name-prefix output.txt");
        }
        String prefix = args[0];
        StringBuilder report = new StringBuilder();
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            if (!function.getName().startsWith(prefix)) {
                continue;
            }
            report.append("function ").append(function.getName())
                  .append(" entry=").append(function.getEntryPoint())
                  .append(" body_size=").append(function.getBody().getNumAddresses())
                  .append('\n');
            InstructionIterator instructions = currentProgram.getListing()
                .getInstructions(function.getBody(), true);
            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                byte[] bytes = instruction.getBytes();
                report.append("  ").append(instruction.getAddress()).append("  ");
                for (byte value : bytes) {
                    report.append(String.format("%02x", value & 0xff));
                }
                report.append("  ").append(instruction).append('\n');
            }
        }
        Path output = Path.of(args[1]);
        Files.createDirectories(output.toAbsolutePath().getParent());
        Files.writeString(output, report.toString(), StandardCharsets.UTF_8);
        println("SMK37 listing report written: " + output);
    }
}
