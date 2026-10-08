// Export imported ELF function names, addresses, and body sizes.
// @category SMK37

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class Smk37FunctionReport extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: Smk37FunctionReport.java output.txt");
        }
        StringBuilder report = new StringBuilder();
        report.append("program=").append(currentProgram.getName()).append('\n');
        report.append("language=").append(currentProgram.getLanguageID()).append('\n');
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        long count = 0;
        while (functions.hasNext()) {
            Function function = functions.next();
            report.append("function=").append(function.getName())
                  .append(" entry=").append(function.getEntryPoint())
                  .append(" size=").append(function.getBody().getNumAddresses())
                  .append('\n');
            count++;
        }
        report.insert(0, "functions=" + count + "\n");
        Path output = Path.of(args[0]);
        Files.createDirectories(output.toAbsolutePath().getParent());
        Files.writeString(output, report.toString(), StandardCharsets.UTF_8);
        println("SMK37 function report written: " + output);
    }
}
