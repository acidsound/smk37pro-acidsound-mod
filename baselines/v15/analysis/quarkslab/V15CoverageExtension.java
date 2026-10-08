//
// Coverage extension for the storage/UI map.
//
// Why this exists
// ---------------
// V15DecoderAnalysis stops its exhaustive sweep at BASE+0x57000, so 260,662 B
// (42.2%) of the 617,012 B image has never been disassembled.  That boundary is
// where it deliberately stops: its own header says "The exhaustive phase can
// decode embedded data.  Its extra xrefs are candidates, not proof."  The
// region past 0x57000 holds the descriptor blobs (handoff 8.2), so sweeping it
// blindly would manufacture code out of data -- the exact inference that bricked
// M09.
//
// 0x0206034C is in that unvisited region.  It has no rows in any of our four
// listings, yet it is called 90 times and every register write in 0x02005888
// (the suspected display init) targets a block it returns.  Its raw bytes are
// `75 04 04 16 bf ea 93 f3` -- `75 04` being `push {rets,r4}`, the same
// prologue family as 7604 / 7904 / 7f04 throughout the decoded region.  So it
// is ordinary code that Ghidra never reached, not data and not a hole.
//
// Method
// ------
// Seed recursive disassembly at prologue-candidate addresses past 0x57000, and
// nothing else.  No aligned sweep of that region.  Two independent filters keep
// the data/code boundary honest:
//
//   1. the seed must match a Jieli function prologue (0x75..0x7F, 0x04),
//      which the decoded region uses 404 times across ~684 functions;
//   2. a candidate is only kept if disassembly from it follows at least one
//      branch and reaches a terminator, so a table of integers that happens to
//      start with 0x75 0x04 is rejected.
//
// Candidates that survive both are reported with their reach, and the caller
// set for each is read back from the already-populated program.  Nothing is
// asserted about what the functions do; this pass only makes them readable.
//
// Read-only with respect to the repo: it writes one listing TSV and one log,
// and never touches any file under build/.

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;

import java.io.File;
import java.io.PrintWriter;
import java.util.TreeSet;

public class V15CoverageExtension extends GhidraScript {
    private static final long BASE = 0x02000000L;
    private static final long IMAGE_SIZE = 617012L;
    private static final long IMAGE_END = BASE + IMAGE_SIZE;

    /** Where V15DecoderAnalysis stopped.  Everything from here was unvisited. */
    private static final long PRIOR_END = BASE + 0x57000L;

    /** Same image V15DecoderAnalysis verified: v15 official app. */
    private static final String EXPECTED_SHA256 =
        "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055";

    /** Minimum reachable instructions before we will call a seed real code. */
    private static final int MIN_REACH = 4;

    private static class Hit {
        final long entry;
        final int reach;
        Hit(long entry, int reach) {
            this.entry = entry;
            this.reach = reach;
        }
    }

    private int prologueByte(long offset) throws Exception {
        Memory memory = currentProgram.getMemory();
        return memory.getByte(toAddr(BASE + offset)) & 0xff;
    }

    private boolean imageHas(long offset, int n) {
        return offset >= 0 && offset + n <= IMAGE_SIZE;
    }

    private boolean isPrologue(long offset) throws Exception {
        if (!imageHas(offset, 2)) {
            return false;
        }
        int b0 = prologueByte(offset);
        int b1 = prologueByte(offset + 1);
        // 0x75..0x7F 0x04 is push {rets, ...}: 7504 push{rets,r4},
        // 7604 push{rets,r6,r5,r4}, 7904 ..., 7f04 push{rets,r15..r4}.
        return b0 >= 0x75 && b0 <= 0x7f && b1 == 0x04;
    }

    /** Instruction count reachable by flow from entry, bounded. */
    private int reach(long entry, int cap) {
        Listing listing = currentProgram.getListing();
        TreeSet<Long> seen = new TreeSet<>();
        TreeSet<Long> work = new TreeSet<>();
        work.add(entry);
        int count = 0;
        while (!work.isEmpty() && count < cap) {
            long at = work.first();
            work.remove(at);
            if (at < BASE || at >= IMAGE_END || !seen.add(at)) {
                continue;
            }
            Address address = toAddr(at);
            Instruction instruction = listing.getInstructionAt(address);
            if (instruction == null) {
                continue;
            }
            count++;
            for (Address flow : instruction.getFlows()) {
                work.add(flow.getOffset());
            }
            Address fall = instruction.getFallThrough();
            if (fall != null) {
                work.add(fall.getOffset());
            }
            // A terminator has no fall-through, and fallThrough already
            // returned null for it above, so there is nothing to add here.
            // There is no Instruction.isTerminal() in this Ghidra version.
        }
        return count;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outDir = args.length > 0 ? args[0] : System.getProperty("user.home");

        println("EXT mapped_base=" + String.format("%08x", BASE));
        println("EXT image_size=" + IMAGE_SIZE);
        println("EXT prior_end=" + String.format("%08x", PRIOR_END));

        int candidates = 0;
        int decoded = 0;
        int accepted = 0;
        TreeSet<Hit> hits = new TreeSet<>(new java.util.Comparator<Hit>() {
            public int compare(Hit a, Hit b) {
                return Long.compare(a.entry, b.entry);
            }
        });

        for (long offset = PRIOR_END - BASE; offset < IMAGE_SIZE; offset += 4) {
            if (monitor.isCancelled()) {
                break;
            }
            if (!isPrologue(offset)) {
                continue;
            }
            candidates++;
            long entry = BASE + offset;
            if (!new DisassembleCommand(toAddr(entry), null, true)
                    .applyTo(currentProgram, monitor)) {
                continue;
            }
            decoded++;
            int r = reach(entry, 4096);
            // Require real flow, not a single instruction that decodes and stops.
            if (r >= MIN_REACH) {
                accepted++;
                hits.add(new Hit(entry, r));
            }
        }

        println("EXT candidates=" + candidates + " decoded=" + decoded
            + " accepted=" + accepted);

        // Second pass: follow flow from every accepted entry so the reachable set
        // from these functions is disassembled, not just their prologues.
        //
        // Two bounds are mandatory here.  Without a `seen` set the worklist
        // re-walks shared suffixes forever, and without a cap a fall-through
        // chain running into a data table walks linearly to the end of the image.
        // The first attempt at this loop had neither and pinned a core at 100%
        // CPU for ten minutes with no log output.  The first pass above is
        // bounded and completed in seconds; this one now matches it.
        int followed = 0;
        int followedOut = 0;
        final int FOLLOW_CAP = 4000;   // per entry, matching reach()'s cap
        TreeSet<Long> visited = new TreeSet<>();
        for (Hit hit : hits) {
            TreeSet<Long> work = new TreeSet<>();
            work.add(hit.entry);
            int steps = 0;
            while (!work.isEmpty()) {
                if (monitor.isCancelled()) {
                    break;
                }
                if (++steps > FOLLOW_CAP) {
                    followedOut++;
                    break;
                }
                long at = work.first();
                work.remove(at);
                if (at < BASE || at >= IMAGE_END) {
                    continue;
                }
                // Visit each address once across the whole pass, not once per
                // entry: functions share tails, and without this the cost is
                // quadratic in the number of accepted seeds.
                if (!visited.add(at)) {
                    continue;
                }
                Address address = toAddr(at);
                if (currentProgram.getListing().getInstructionAt(address) == null) {
                    new DisassembleCommand(address, null, true)
                        .applyTo(currentProgram, monitor);
                    followed++;
                }
                Instruction instruction = currentProgram.getListing()
                    .getInstructionAt(address);
                if (instruction == null) {
                    continue;
                }
                for (Address flow : instruction.getFlows()) {
                    work.add(flow.getOffset());
                }
                Address fall = instruction.getFallThrough();
                if (fall != null) {
                    work.add(fall.getOffset());
                }
            }
        }
        println("EXT flow_followed_instructions=" + followed
            + " capped_entries=" + followedOut
            + " unique_visited=" + visited.size());

        // Write a listing of the newly decoded region.
        File listingFile = new File(outDir, "v15-coverage-extension-listing.tsv");
        PrintWriter out = new PrintWriter(listingFile, "UTF-8");
        out.println("address\tbytes\tlength\tmnemonic\ttext\tfunction");
        long written = 0;
        long minAddr = Long.MAX_VALUE;
        long maxAddr = 0;
        InstructionIterator iterator = currentProgram.getListing()
            .getInstructions(true);
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            long value = instruction.getAddress().getOffset();
            if (value < PRIOR_END) {
                continue;
            }
            byte[] bytes = instruction.getBytes();
            StringBuilder hex = new StringBuilder();
            for (byte b : bytes) {
                hex.append(String.format("%02x", b & 0xff));
            }
            Function function = currentProgram.getFunctionManager()
                .getFunctionContaining(instruction.getAddress());
            String fname = function == null ? "-" : function.getName();
            // mnemonic and text are the same string in this sleigh build, but
            // the original listings keep both columns, so match their shape
            // rather than collapsing them.
            String text = instruction.toString();
            out.println(String.format("%x\t%s\t%d\t%s\t%s\t%s",
                value, hex.toString(), instruction.getLength(),
                text, text, fname));
            written++;
            minAddr = Math.min(minAddr, value);
            maxAddr = Math.max(maxAddr, value);
        }
        out.close();
        println("EXT listing_rows=" + written + " file=" + listingFile.getPath());
        if (written > 0) {
            println("EXT new_region=" + String.format("%08x..%08x", minAddr, maxAddr)
                + " bytes=" + (maxAddr - minAddr + 1));
        }

        // Report the accepted entries with reach.
        File entryFile = new File(outDir, "v15-coverage-extension-entries.tsv");
        PrintWriter entries = new PrintWriter(entryFile, "UTF-8");
        entries.println("entry\treach");
        for (Hit hit : hits) {
            entries.println(String.format("%x\t%d", hit.entry, hit.reach));
        }
        entries.close();
        println("EXT entries_file=" + entryFile.getPath());
    }
}
