// Report every reference whose destination falls inside an address range.
// @category SMK37

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class Smk37RangeReferences extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException(
                "usage: Smk37RangeReferences.java start length output.txt");
        }
        Address start = toAddr(Long.decode(args[0]));
        int length = Integer.decode(args[1]);
        Address end = start.add(length - 1L);

        StringBuilder report = new StringBuilder();
        report.append("range=").append(start).append("..").append(end).append('\n');
        int count = 0;
        for (Address cursor = start;
             cursor.compareTo(end) <= 0;
             cursor = cursor.next()) {
            for (Reference reference : getReferencesTo(cursor)) {
                report.append("to=").append(cursor)
                    .append(" from=").append(reference.getFromAddress())
                    .append(" type=").append(reference.getReferenceType())
                    .append('\n');
                count++;
            }
        }
        report.append("count=").append(count).append('\n');

        Path output = Path.of(args[2]);
        Files.createDirectories(output.toAbsolutePath().getParent());
        Files.writeString(output, report.toString(), StandardCharsets.UTF_8);
        println("SMK37 range-reference report written: " + output);
    }
}
