// Emit repeatable Pi32v2 analysis counts and references to musical/UI anchors.
// @category SMK37

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

public class Smk37Report extends GhidraScript {
    private static final String[] ANCHORS = {
        "Drum Seq",
        "Sequencer",
        "midi_route",
        "Note Repeat",
        "Clear Pattern",
        "Algorithm-",
        "Mono/Poly",
        "drum"
    };

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: Smk37Report.java output.txt");
        }

        long instructionCount = 0;
        InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
        while (instructions.hasNext()) {
            instructions.next();
            instructionCount++;
        }

        long functionCount = 0;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            functions.next();
            functionCount++;
        }

        StringBuilder report = new StringBuilder();
        report.append("program=").append(currentProgram.getName()).append('\n');
        report.append("language=").append(currentProgram.getLanguageID()).append('\n');
        report.append("image_base=").append(currentProgram.getImageBase()).append('\n');
        report.append("instructions=").append(instructionCount).append('\n');
        report.append("functions=").append(functionCount).append('\n');

        Memory memory = currentProgram.getMemory();
        for (String anchor : ANCHORS) {
            byte[] needle = anchor.getBytes(StandardCharsets.US_ASCII);
            Address cursor = currentProgram.getMinAddress();
            while (cursor != null) {
                Address found = memory.findBytes(cursor, needle, null, true, monitor);
                if (found == null) {
                    break;
                }
                report.append("anchor=").append(anchor)
                      .append(" address=").append(found);
                ReferenceIterator references = currentProgram.getReferenceManager().getReferencesTo(found);
                int count = 0;
                while (references.hasNext()) {
                    Reference reference = references.next();
                    report.append(" ref=").append(reference.getFromAddress());
                    Function function = getFunctionContaining(reference.getFromAddress());
                    if (function != null) {
                        report.append("[").append(function.getName()).append("]");
                    }
                    count++;
                }
                report.append(" refs=").append(count).append('\n');

                byte[] pointer = ByteBuffer.allocate(4)
                    .order(ByteOrder.LITTLE_ENDIAN)
                    .putInt((int)found.getOffset())
                    .array();
                Address pointerCursor = currentProgram.getMinAddress();
                while (pointerCursor != null) {
                    Address pointerFound = memory.findBytes(
                        pointerCursor, pointer, null, true, monitor);
                    if (pointerFound == null) {
                        break;
                    }
                    report.append("pointer_to=").append(anchor)
                          .append(" at=").append(pointerFound);
                    Instruction instruction = currentProgram.getListing()
                        .getInstructionContaining(pointerFound);
                    if (instruction != null) {
                        report.append(" instruction=").append(instruction.getAddress())
                              .append(":").append(instruction);
                    }
                    Function pointerFunction = getFunctionContaining(pointerFound);
                    if (pointerFunction != null) {
                        report.append(" function=").append(pointerFunction.getName());
                    }
                    report.append('\n');
                    pointerCursor = pointerFound.next();
                }
                cursor = found.next();
            }
        }

        Path output = Path.of(args[0]);
        Files.createDirectories(output.toAbsolutePath().getParent());
        Files.writeString(output, report.toString(), StandardCharsets.UTF_8);
        println("SMK37 report written: " + output);
    }
}
