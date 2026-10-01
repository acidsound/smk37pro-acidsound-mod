// @category SMK37
// v16 (1.16) PI32v2 decoder listing and USB MIDI / UI-label evidence probe.
// Derived from V15DecoderAnalysis.java; only image constants and target addresses differ.
//
// This script deliberately reports two phases:
//   1. recursive: entry plus internal-pointer seeds, with normal flow following
//   2. exhaustive: an aligned sweep over the pre-evidence region
//
// The exhaustive phase can decode embedded data.  Its extra xrefs are candidates,
// not proof, and are kept separate from the recursive results.

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

public class V16DecoderAnalysis extends GhidraScript {
    private static final long BASE = 0x02000000L;
    private static final long IMAGE_SIZE = 619704L;
    private static final long IMAGE_END = BASE + IMAGE_SIZE;
    // v15 used BASE+0x57000 as the code/data boundary.  The v16 insertion map shows
    // code shifts of up to +2506 (0x9CA) at the tail of the code region, so the
    // sweep window is extended by 0x1000 to cover it.
    private static final long RECURSIVE_SEED_LIMIT = BASE + 0x58000L;
    private static final long EXHAUSTIVE_END = BASE + 0x58000L;
    private static final long EVIDENCE_REGION_START = BASE + 0x58000L;
    private static final long EVIDENCE_REGION_END = BASE + 0x59000L;
    private static final String EXPECTED_SHA256 =
        "0f64fbf6ffc454eea686d78cf89f35e593229765bdcf166f10a8bd714abcb09a";

    private static class Target {
        final String name;
        final long start;
        final int length;

        Target(String name, long start, int length) {
            this.name = name;
            this.start = start;
            this.length = length;
        }

        long endExclusive() {
            return start + length;
        }

        boolean contains(long value) {
            return value >= start && value < endExclusive();
        }
    }

    // Addresses are verified by exact byte-match of the v15 target bytes inside the
    // decoded v16 image (see ../v15-vs-v16-app-diff-2026-10-01/target-map.json).
    private static final Target[] TARGETS = new Target[] {
        new Target("midi_route_ascii", 0x02058121L, 11),
        new Target("midi_streaming_interface", 0x020583aeL, 9),
        new Target("midi_streaming_header", 0x020583b7L, 7),
        new Target("usb_midi_cin_payload_lengths", 0x020584b0L, 16),
        new Target("usb_device_descriptor", 0x02058553L, 18),
        new Target("midi_product_utf16le", 0x020589e6L, 30),
        new Target("midi_in_endpoint", 0x02058a04L, 9),
        new Target("midi_in_cs_endpoint", 0x02058a0dL, 7),
        new Target("midi_out_endpoint", 0x02058a14L, 9),
        new Target("midi_out_cs_endpoint", 0x02058a1dL, 7),
        new Target("midi_jack_graph", 0x02058c82L, 90),
        new Target("ui_label_local", 0x0205e2d3L, 7),
        new Target("ui_label_usb_rec", 0x0205e32aL, 8),
        new Target("ui_label_key_chn", 0x0205e2e2L, 8),
        new Target("ui_label_pad_chn", 0x0205e2ebL, 8),
    };

    private long u32le(Memory memory, Address address) throws Exception {
        byte[] bytes = new byte[4];
        memory.getBytes(address, bytes);
        return ((long) bytes[0] & 0xff)
            | (((long) bytes[1] & 0xff) << 8)
            | (((long) bytes[2] & 0xff) << 16)
            | (((long) bytes[3] & 0xff) << 24);
    }

    private String sha256(Memory memory) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[65536];
        long cursor = BASE;
        while (cursor < IMAGE_END) {
            int length = (int) Math.min(buffer.length, IMAGE_END - cursor);
            int read = memory.getBytes(toAddr(cursor), buffer, 0, length);
            if (read != length) {
                throw new IllegalStateException("short memory read at " + toAddr(cursor));
            }
            digest.update(buffer, 0, length);
            cursor += length;
        }
        StringBuilder result = new StringBuilder();
        for (byte value : digest.digest()) {
            result.append(String.format("%02x", value & 0xff));
        }
        return result.toString();
    }

    private TreeSet<Long> pointerSeeds(Memory memory) throws Exception {
        TreeSet<Long> seeds = new TreeSet<>();
        seeds.add(BASE);
        for (long source = BASE; source + 3 < IMAGE_END; source += 2) {
            long value = u32le(memory, toAddr(source));
            if ((value & 1) == 0 && value >= BASE && value < RECURSIVE_SEED_LIMIT) {
                seeds.add(value);
            }
        }
        return seeds;
    }

    private int disassembleSeeds(TreeSet<Long> seeds) {
        int accepted = 0;
        for (long seed : seeds) {
            if (monitor.isCancelled()) {
                break;
            }
            if (new DisassembleCommand(toAddr(seed), null, true)
                    .applyTo(currentProgram, monitor)) {
                accepted++;
            }
        }
        return accepted;
    }

    private int exhaustiveSweep(Listing listing) {
        int attempted = 0;
        int accepted = 0;
        for (long value = BASE; value < EXHAUSTIVE_END; value += 2) {
            if (monitor.isCancelled()) {
                break;
            }
            Address address = toAddr(value);
            if (listing.getInstructionContaining(address) != null) {
                continue;
            }
            attempted++;
            if (new DisassembleCommand(address, null, true)
                    .applyTo(currentProgram, monitor)) {
                accepted++;
            }
        }
        println("SWEEP attempted=" + attempted + " accepted=" + accepted);
        return accepted;
    }

    private String functionName(FunctionManager functions, Address address) {
        Function function = functions.getFunctionContaining(address);
        if (function == null) {
            return "-";
        }
        return function.getName() + "@" + function.getEntryPoint();
    }

    private String bytesHex(Memory memory, Instruction instruction) {
        try {
            byte[] bytes = new byte[instruction.getLength()];
            memory.getBytes(instruction.getAddress(), bytes);
            StringBuilder result = new StringBuilder();
            for (byte value : bytes) {
                result.append(String.format("%02x", value & 0xff));
            }
            return result.toString();
        }
        catch (Exception error) {
            return "ERROR:" + error.getClass().getSimpleName();
        }
    }

    private String clean(String text) {
        return text.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }

    private void exportListing(String outputPrefix, String phase, Memory memory,
            Listing listing, FunctionManager functions) throws Exception {
        File output = new File(outputPrefix + "-" + phase + "-listing.tsv");
        File parent = output.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create output directory " + parent);
        }
        try (PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(output)))) {
            writer.println("address\tbytes\tlength\tmnemonic\ttext\tflow_type\tfunction");
            InstructionIterator instructions = listing.getInstructions(true);
            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                long value = instruction.getAddress().getOffset();
                if (value < BASE || value >= EXHAUSTIVE_END) {
                    continue;
                }
                writer.println(instruction.getAddress() + "\t"
                    + bytesHex(memory, instruction) + "\t"
                    + instruction.getLength() + "\t"
                    + clean(instruction.getMnemonicString()) + "\t"
                    + clean(instruction.toString()) + "\t"
                    + clean(instruction.getFlowType().toString()) + "\t"
                    + clean(functionName(functions, instruction.getAddress())));
            }
        }
        println("LISTING phase=" + phase + " path=" + output.getAbsolutePath());
    }

    private void printRawTargetPointers(Memory memory, Target target) throws Exception {
        int exactCount = 0;
        int rangeCount = 0;
        for (long source = BASE; source + 3 < IMAGE_END; source++) {
            long value = u32le(memory, toAddr(source));
            if (value == target.start) {
                println("RAW_POINTER target=" + target.name + " source=" + toAddr(source)
                    + " value=" + toAddr(value) + " kind=exact");
                exactCount++;
            }
            else if (target.contains(value)) {
                println("RAW_POINTER target=" + target.name + " source=" + toAddr(source)
                    + " value=" + toAddr(value) + " kind=interior");
                rangeCount++;
            }
        }
        println("RAW_POINTER_COUNT target=" + target.name + " exact=" + exactCount
            + " interior=" + rangeCount);
    }

    private void printTargetReferences(String phase, Target target,
            ReferenceManager references, FunctionManager functions) {
        int exactCount = 0;
        ReferenceIterator exact = references.getReferencesTo(toAddr(target.start));
        while (exact.hasNext()) {
            Reference reference = exact.next();
            println("TARGET_XREF phase=" + phase + " target=" + target.name
                + " from=" + reference.getFromAddress()
                + " to=" + reference.getToAddress()
                + " type=" + reference.getReferenceType()
                + " source=" + reference.getSource()
                + " function=" + functionName(functions, reference.getFromAddress()));
            exactCount++;
        }

        int interiorCount = 0;
        for (long value = target.start + 1; value < target.endExclusive(); value++) {
            ReferenceIterator interior = references.getReferencesTo(toAddr(value));
            while (interior.hasNext()) {
                Reference reference = interior.next();
                println("TARGET_XREF phase=" + phase + " target=" + target.name
                    + " from=" + reference.getFromAddress()
                    + " to=" + reference.getToAddress()
                    + " type=" + reference.getReferenceType()
                    + " source=" + reference.getSource()
                    + " function=" + functionName(functions, reference.getFromAddress()));
                interiorCount++;
            }
        }
        println("TARGET_XREF_COUNT phase=" + phase + " target=" + target.name
            + " exact=" + exactCount + " interior=" + interiorCount);
    }

    private boolean valueInEvidence(long value) {
        return value >= EVIDENCE_REGION_START && value < EVIDENCE_REGION_END;
    }

    private void reportPhase(String phase, Memory memory, Listing listing,
            ReferenceManager references, FunctionManager functions) throws Exception {
        long instructionCount = 0;
        long instructionBytes = 0;
        long callInstructions = 0;
        long callReferences = 0;
        long branchInstructions = 0;
        long computedFlows = 0;
        long noPcodeInstructions = 0;
        long pcodeFailures = 0;
        long evidenceReferences = 0;
        long evidenceScalars = 0;
        long evidencePcodeConstants = 0;
        Map<Integer, Long> sizeHistogram = new TreeMap<>();
        Map<String, Long> mnemonicHistogram = new TreeMap<>();

        InstructionIterator instructions = listing.getInstructions(true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            long addressValue = instruction.getAddress().getOffset();
            if (addressValue < BASE || addressValue >= EXHAUSTIVE_END) {
                continue;
            }
            instructionCount++;
            instructionBytes += instruction.getLength();
            sizeHistogram.put(instruction.getLength(),
                sizeHistogram.getOrDefault(instruction.getLength(), 0L) + 1);
            String mnemonic = instruction.getMnemonicString();
            mnemonicHistogram.put(mnemonic, mnemonicHistogram.getOrDefault(mnemonic, 0L) + 1);

            if (instruction.getFlowType().isCall()) {
                callInstructions++;
            }
            if (instruction.getFlowType().isJump()) {
                branchInstructions++;
            }
            if (instruction.getFlowType().isComputed()) {
                computedFlows++;
            }

            for (Reference reference : instruction.getReferencesFrom()) {
                if (reference.getReferenceType().isCall()) {
                    callReferences++;
                }
                Address target = reference.getToAddress();
                if (target != null && valueInEvidence(target.getOffset())) {
                    println("EVIDENCE_REF phase=" + phase
                        + " from=" + instruction.getAddress()
                        + " text=" + clean(instruction.toString())
                        + " to=" + target
                        + " type=" + reference.getReferenceType()
                        + " function=" + functionName(functions, instruction.getAddress()));
                    evidenceReferences++;
                }
            }

            for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
                for (Object object : instruction.getOpObjects(operand)) {
                    if (object instanceof Scalar) {
                        long value = ((Scalar) object).getUnsignedValue();
                        if (valueInEvidence(value)) {
                            println("EVIDENCE_SCALAR phase=" + phase
                                + " at=" + instruction.getAddress()
                                + " value=" + toAddr(value)
                                + " text=" + clean(instruction.toString())
                                + " function=" + functionName(functions, instruction.getAddress()));
                            evidenceScalars++;
                        }
                    }
                }
            }

            try {
                PcodeOp[] pcode = instruction.getPcode();
                if (pcode.length == 0) {
                    noPcodeInstructions++;
                }
                for (PcodeOp operation : pcode) {
                    for (Varnode input : operation.getInputs()) {
                        if (input != null && input.isConstant()
                                && valueInEvidence(input.getOffset())) {
                            println("EVIDENCE_PCODE_CONST phase=" + phase
                                + " at=" + instruction.getAddress()
                                + " value=" + toAddr(input.getOffset())
                                + " op=" + operation.getMnemonic()
                                + " text=" + clean(instruction.toString())
                                + " function=" + functionName(functions, instruction.getAddress()));
                            evidencePcodeConstants++;
                        }
                    }
                }
            }
            catch (Exception error) {
                pcodeFailures++;
                println("PCODE_FAILURE phase=" + phase + " at=" + instruction.getAddress()
                    + " error=" + clean(error.toString()));
            }
        }

        long undecodedEvenSlots = 0;
        for (long value = BASE; value < EXHAUSTIVE_END; value += 2) {
            if (listing.getInstructionContaining(toAddr(value)) == null) {
                undecodedEvenSlots++;
            }
        }

        println("PHASE " + phase);
        println("METRIC phase=" + phase + " key=instruction_count value=" + instructionCount);
        println("METRIC phase=" + phase + " key=instruction_bytes value=" + instructionBytes);
        println("METRIC phase=" + phase + " key=code_region_bytes value=" + (EXHAUSTIVE_END - BASE));
        println("METRIC phase=" + phase + " key=undecoded_even_slots value=" + undecodedEvenSlots);
        println("METRIC phase=" + phase + " key=function_count value=" + functions.getFunctionCount());
        println("METRIC phase=" + phase + " key=call_instruction_count value=" + callInstructions);
        println("METRIC phase=" + phase + " key=direct_call_reference_count value=" + callReferences);
        println("METRIC phase=" + phase + " key=branch_instruction_count value=" + branchInstructions);
        println("METRIC phase=" + phase + " key=computed_flow_count value=" + computedFlows);
        println("METRIC phase=" + phase + " key=no_pcode_instruction_count value=" + noPcodeInstructions);
        println("METRIC phase=" + phase + " key=pcode_exception_count value=" + pcodeFailures);
        println("METRIC phase=" + phase + " key=evidence_reference_count value=" + evidenceReferences);
        println("METRIC phase=" + phase + " key=evidence_scalar_count value=" + evidenceScalars);
        println("METRIC phase=" + phase + " key=evidence_pcode_constant_count value=" + evidencePcodeConstants);
        println("HISTOGRAM phase=" + phase + " key=instruction_size value=" + sizeHistogram);
        println("HISTOGRAM phase=" + phase + " key=mnemonic value=" + mnemonicHistogram);

        for (Target target : TARGETS) {
            printTargetReferences(phase, target, references, functions);
        }
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: V15DecoderAnalysis.java OUTPUT_PREFIX");
        }
        String outputPrefix = args[0];

        if (!currentProgram.getLanguageID().toString().equals("pi32v2:LE:32:default")) {
            throw new IllegalStateException("expected pi32v2:LE:32:default, got "
                + currentProgram.getLanguageID());
        }
        if (currentProgram.getMinAddress().getOffset() != BASE) {
            throw new IllegalStateException("expected mapped memory base " + toAddr(BASE)
                + ", got " + currentProgram.getMinAddress());
        }

        Memory memory = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        ReferenceManager references = currentProgram.getReferenceManager();
        FunctionManager functions = currentProgram.getFunctionManager();

        String digest = sha256(memory);
        if (!digest.equals(EXPECTED_SHA256)) {
            throw new IllegalStateException("unexpected image SHA-256 " + digest);
        }
        println("PROVENANCE image_sha256=" + digest);
        println("PROVENANCE mapped_memory_base=" + currentProgram.getMinAddress());
        println("PROVENANCE program_image_base_metadata=" + currentProgram.getImageBase());
        println("PROVENANCE image_size=" + IMAGE_SIZE);
        println("PROVENANCE language=" + currentProgram.getLanguageID());
        println("PROVENANCE script_args=" + Arrays.toString(args));

        for (Target target : TARGETS) {
            printRawTargetPointers(memory, target);
        }

        TreeSet<Long> seeds = pointerSeeds(memory);
        int acceptedSeeds = disassembleSeeds(seeds);
        println("RECURSIVE pointer_derived_seeds=" + seeds.size()
            + " accepted=" + acceptedSeeds);
        analyzeAll(currentProgram);
        reportPhase("recursive", memory, listing, references, functions);
        exportListing(outputPrefix, "recursive", memory, listing, functions);

        exhaustiveSweep(listing);
        analyzeAll(currentProgram);
        reportPhase("exhaustive", memory, listing, references, functions);
        exportListing(outputPrefix, "exhaustive", memory, listing, functions);
    }
}
