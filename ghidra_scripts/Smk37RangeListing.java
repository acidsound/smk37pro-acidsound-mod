// Export raw bytes and any decoded instructions for an address range.
// @category SMK37

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class Smk37RangeListing extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException(
                "usage: Smk37RangeListing.java start length output.txt");
        }
        Address start = toAddr(Long.decode(args[0]));
        int length = Integer.decode(args[1]);
        Address end = start.add(length - 1L);
        disassemble(start);

        StringBuilder report = new StringBuilder();
        report.append("range=").append(start).append("..").append(end).append('\n');
        Address cursor = start;
        while (cursor.compareTo(end) <= 0) {
            Instruction instruction = getInstructionAt(cursor);
            if (instruction != null) {
                byte[] bytes = instruction.getBytes();
                report.append(cursor).append("  ");
                for (byte value : bytes) {
                    report.append(String.format("%02x", value & 0xff));
                }
                report.append("  ").append(instruction).append('\n');
                cursor = cursor.add(bytes.length);
            } else {
                int remaining = (int)Math.min(2L, end.subtract(cursor) + 1L);
                byte[] bytes = getBytes(cursor, remaining);
                report.append(cursor).append("  ");
                for (byte value : bytes) {
                    report.append(String.format("%02x", value & 0xff));
                }
                report.append("  .raw\n");
                cursor = cursor.add(remaining);
            }
        }

        Path output = Path.of(args[2]);
        Files.createDirectories(output.toAbsolutePath().getParent());
        Files.writeString(output, report.toString(), StandardCharsets.UTF_8);
        println("SMK37 range listing written: " + output);
    }
}
