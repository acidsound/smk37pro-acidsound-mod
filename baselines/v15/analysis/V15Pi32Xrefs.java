// @category SMK37
// Clean-room v15 xref probe for patched kagaimiq/ghidra-jieli pi32v2.
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import java.util.TreeSet;

public class V15Pi32Xrefs extends GhidraScript {
    private static final long BASE = 0x02000000L;
    private static final long IMAGE_SIZE = 617012L;
    private static final long POINTER_SEED_LIMIT = BASE + 0x57000L;

    private long u32le(Memory memory, Address address) throws Exception {
        byte[] bytes = new byte[4];
        memory.getBytes(address, bytes);
        return ((long) bytes[0] & 0xff)
            | (((long) bytes[1] & 0xff) << 8)
            | (((long) bytes[2] & 0xff) << 16)
            | (((long) bytes[3] & 0xff) << 24);
    }

    private void printTarget(ReferenceManager references, String name, long value) {
        Address target = toAddr(value);
        println("TARGET " + name + " " + target);
        ReferenceIterator iterator = references.getReferencesTo(target);
        int count = 0;
        while (iterator.hasNext()) {
            Reference reference = iterator.next();
            println("  XREF " + reference.getFromAddress()
                + " type=" + reference.getReferenceType()
                + " source=" + reference.getSource());
            count++;
        }
        println("  XREF_COUNT " + count);
    }

    @Override
    protected void run() throws Exception {
        if (!currentProgram.getLanguageID().toString().equals("pi32v2:LE:32:default")) {
            throw new IllegalStateException("expected pi32v2:LE:32:default");
        }

        Memory memory = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        ReferenceManager references = currentProgram.getReferenceManager();
        TreeSet<Long> seeds = new TreeSet<>();
        seeds.add(BASE);

        // Heuristic only: internal even pointers into the pre-rodata region are
        // useful disassembly seeds. They are not asserted to be function entries.
        for (long source = BASE; source + 3 < BASE + IMAGE_SIZE; source += 2) {
            long value = u32le(memory, toAddr(source));
            if ((value & 1) == 0 && value >= BASE && value < POINTER_SEED_LIMIT) {
                seeds.add(value);
            }
        }

        int accepted = 0;
        for (long seed : seeds) {
            if (new DisassembleCommand(toAddr(seed), null, true)
                    .applyTo(currentProgram, monitor)) {
                accepted++;
            }
        }
        analyzeAll(currentProgram);

        long instructionCount = 0;
        InstructionIterator instructions = listing.getInstructions(true);
        while (instructions.hasNext()) {
            instructions.next();
            instructionCount++;
        }
        println("LANGUAGE " + currentProgram.getLanguageID());
        println("POINTER_DERIVED_SEEDS " + seeds.size());
        println("SEEDS_ACCEPTED " + accepted);
        println("INSTRUCTION_COUNT " + instructionCount);

        int callInstructionCount = 0;
        int directCallReferenceCount = 0;
        instructions = listing.getInstructions(true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            if (!instruction.getFlowType().isCall()) {
                continue;
            }
            callInstructionCount++;
            for (Reference reference : instruction.getReferencesFrom()) {
                if (reference.getReferenceType().isCall()) {
                    directCallReferenceCount++;
                }
            }
        }
        println("CALL_INSTRUCTION_COUNT " + callInstructionCount);
        println("DIRECT_CALL_REFERENCE_COUNT " + directCallReferenceCount);

        printTarget(references, "midi_route_ascii", 0x0205773bL);
        printTarget(references, "midi_streaming_interface", 0x020579aeL);
        printTarget(references, "usb_midi_cin_payload_lengths", 0x02057ab0L);
        printTarget(references, "usb_device_descriptor", 0x02057b53L);
        printTarget(references, "midi_product_utf16le", 0x02057fa8L);
        printTarget(references, "midi_in_endpoint", 0x02057fc6L);
        printTarget(references, "midi_out_endpoint", 0x02057fd6L);
        printTarget(references, "midi_jack_graph", 0x02058274L);

        int regionReferences = 0;
        instructions = listing.getInstructions(true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            for (Reference reference : instruction.getReferencesFrom()) {
                Address target = reference.getToAddress();
                if (target == null) {
                    continue;
                }
                long value = target.getOffset();
                if (value >= 0x02057000L && value < 0x02058500L) {
                    println("REGION_XREF " + instruction.getAddress() + " "
                        + instruction + " -> " + target + " "
                        + reference.getReferenceType());
                    regionReferences++;
                }
            }
        }
        println("REGION_REFERENCE_COUNT " + regionReferences);
    }
}
