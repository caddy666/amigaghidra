// Finds function entry points that Ghidra's auto-analysis missed by scanning for
// three distinct 68k function prologue patterns:
//   1. MOVEM.L Dn/An,-(SP)  (opcode prefix $48E7) — GCC/VBCC/DICE/hand-asm
//   2. LINK A5,#N           (opcode $4E55)         — SAS/C, Lattice C
//   3. LINK A6,#N           (opcode $4E56)         — GCC with -fno-omit-frame-pointer
// At each address that matches a pattern and is not already within a defined function,
// disassembles the code and creates a new function.
// Run after initial auto-analysis to recover compiler-generated functions.
//@author AmigaGhidra
//@category Amiga
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

public class FindMissedFunctions extends GhidraScript {

    @Override
    protected void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();

        int found = 0;
        int skipped = 0;
        int total = 0;

        // Pattern 1: MOVEM.L (SP)- push — high byte $48, low byte $E7 (some saves vary)
        // More precisely: $48E7 followed by any save mask word
        byte[] movemPattern = { 0x48, (byte) 0xE7 };

        // Pattern 2: LINK A5 ($4E55)
        byte[] linkA5 = { 0x4E, 0x55 };

        // Pattern 3: LINK A6 ($4E56)
        byte[] linkA6 = { 0x4E, 0x56 };

        monitor.setMessage("Scanning for missed function prologues...");

        // Helper: scan a pattern and create functions at hits
        for (int pass = 0; pass < 3; pass++) {
            byte[] pattern;
            String pname;
            switch (pass) {
                case 0: pattern = movemPattern; pname = "MOVEM.L -(SP)"; break;
                case 1: pattern = linkA5;       pname = "LINK A5";       break;
                case 2: pattern = linkA6;       pname = "LINK A6";       break;
                default: return;
            }

            Address scanFrom = currentProgram.getMinAddress();
            while (!monitor.isCancelled()) {
                Address hit = find(scanFrom, pattern);
                if (hit == null) break;
                scanFrom = hit.add(2);
                total++;

                // Skip if address is not in an executable block
                MemoryBlock blk = mem.getBlock(hit);
                if (blk == null || !blk.isExecute()) continue;

                // Skip if already within a function
                if (fm.getFunctionContaining(hit) != null) {
                    skipped++;
                    continue;
                }

                // For MOVEM pattern: verify it is not inside a data block
                // (a simple check: must be 2-byte aligned and the preceding instruction
                //  should not be a string/data directive)
                if (listing.getDataAt(hit) != null) continue;

                // Disassemble and create function
                try {
                    disassemble(hit);
                    Function func = createFunction(hit, null);
                    if (func != null) {
                        found++;
                        println(String.format("  %s @ 0x%08X  → %s",
                            pname, hit.getOffset(), func.getName()));
                    }
                } catch (Exception e) {
                    // Not a valid code location — silently skip
                }
            }
        }

        monitor.setMessage("Done.");
        println(String.format("\nMissed function scan: %d new functions created, %d already defined, %d total pattern hits.",
            found, skipped, total));
        if (found == 0) {
            println("No new functions found — auto-analysis may already be complete.");
        }
    }
}
