// Decompile one or more function addresses into a text report.
// @category SMK37

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class Smk37DecompileAddresses extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "usage: Smk37DecompileAddresses.java output.txt address...");
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        StringBuilder report = new StringBuilder();

        for (int index = 1; index < args.length; index++) {
            Address address = toAddr(Long.decode(args[index]));
            Function function = getFunctionContaining(address);
            if (function == null) {
                function = getFunctionAt(address);
            }
            report.append("address=").append(address).append('\n');
            if (function == null) {
                report.append("no function\n\n");
                continue;
            }

            report.append("function=").append(function.getName())
                  .append(" entry=").append(function.getEntryPoint()).append('\n');
            DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
            if (!result.decompileCompleted()) {
                report.append("decompile failed: ")
                      .append(result.getErrorMessage()).append("\n\n");
                continue;
            }
            report.append(result.getDecompiledFunction().getC()).append("\n\n");
        }

        decompiler.dispose();
        Path output = Path.of(args[0]);
        Files.createDirectories(output.toAbsolutePath().getParent());
        Files.writeString(output, report.toString(), StandardCharsets.UTF_8);
        println("SMK37 decompile report written: " + output);
    }
}
