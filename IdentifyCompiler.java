// Identifies the compiler that produced the current Amiga binary by examining
// function prologue patterns, calling conventions, and symbol table heuristics.
//
// Detected compilers and distinguishing patterns:
//   SAS/C 6.x      — LINK A5,#N  +  saves D2-D7/A2-A4  +  absolute globals
//   Lattice C 3/4   — LINK A5,#N  +  saves only D2-D5/A2-A3
//   StormC          — LINK A5,#N  +  __ct__/__dt__ mangled names in HUNK_SYMBOL
//   GCC (frame ptr) — LINK A6,#N  (A6 not A5 = key distinction from SAS/C)
//   GCC/VBCC/DICE   — MOVEM.L -(SP), no LINK
//   Aztec/Manx C    — LEA $DFF000,A4 base pattern, A4 used as small-data base
//   DICE C          — no LINK, entry point named _mainCRTStartup
//   Hand-asm        — no LINK anywhere, direct $DFF000 hardware writes
//
// Prints a verdict to the console with evidence counts.
//@author AmigaGhidra
//@category Amiga
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;

import java.util.*;

public class IdentifyCompiler extends GhidraScript {

    @Override
    protected void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        SymbolTable st = currentProgram.getSymbolTable();
        Memory mem = currentProgram.getMemory();

        // Counters
        int total = 0;
        int linkA5 = 0;       // SAS/C, Lattice, StormC
        int linkA6 = 0;       // GCC with frame pointer
        int movemNoLink = 0;  // GCC/VBCC/DICE
        int noProlog = 0;     // Hand-asm or leaf functions
        int savesWide = 0;    // D2-D7/A2-A4 = SAS/C style (9 regs)
        int savesNarrow = 0;  // D2-D5/A2-A3 = Lattice style (6 regs or fewer)
        int pcRelGlobal = 0;  // LEA x(PC),An = GCC -fpic or VBCC
        int absGlobal = 0;    // MOVEA.L (addr).L,An = SAS/C absolute

        // Symbol heuristics
        boolean hasCRTStartup  = false; // DICE C
        boolean hasMainGCC     = false; // GCC/libnix: __main, __exit
        boolean hasCStart      = false; // SAS/C: _c_start
        boolean hasReturnCode  = false; // SAS/C: _ReturnCode
        boolean hasCtDt        = false; // StormC C++: __ct__/__dt__ mangling

        // Scan symbol table for telltale names
        for (Symbol sym : st.getAllSymbols(false)) {
            String name = sym.getName();
            if (name.equals("_mainCRTStartup"))          hasCRTStartup = true;
            if (name.equals("__main") || name.equals("__exit") || name.equals("__parse_args"))
                hasMainGCC = true;
            if (name.equals("_c_start"))                 hasCStart = true;
            if (name.equals("_ReturnCode"))              hasReturnCode = true;
            if (name.startsWith("__ct__") || name.startsWith("__dt__"))
                hasCtDt = true;
            if (monitor.isCancelled()) break;
        }

        // Scan function prologues
        Listing listing = currentProgram.getListing();
        FunctionIterator fi = fm.getFunctions(true);

        monitor.setMessage("Analyzing function prologues...");
        monitor.initialize(fm.getFunctionCount());

        while (fi.hasNext() && !monitor.isCancelled()) {
            Function func = fi.next();
            monitor.incrementProgress(1);
            total++;

            Address entry = func.getEntryPoint();
            Instruction instr = listing.getInstructionAt(entry);
            if (instr == null) { noProlog++; continue; }

            String mnemonic = instr.getMnemonicString().toLowerCase();

            if (mnemonic.equals("link")) {
                // LINK instruction: which register?
                String regStr = instr.getDefaultOperandRepresentation(0);
                if (regStr != null && regStr.equalsIgnoreCase("A5")) {
                    linkA5++;
                    // Check how many registers are saved in next instruction
                    Instruction next = listing.getInstructionAfter(entry);
                    if (next != null && next.getMnemonicString().equalsIgnoreCase("movem.l")) {
                        // Wide save (SAS/C) vs narrow (Lattice)
                        String ops = next.getDefaultOperandRepresentation(0);
                        int regCount = ops == null ? 0 : countRegisters(ops);
                        if (regCount >= 7) savesWide++;
                        else if (regCount > 0) savesNarrow++;
                    }
                } else if (regStr != null && regStr.equalsIgnoreCase("A6")) {
                    linkA6++;
                }
            } else if (mnemonic.equals("movem.l")) {
                // No LINK — check if this is a push to (SP)
                String ops0 = instr.getDefaultOperandRepresentation(0);
                String ops1 = instr.getDefaultOperandRepresentation(1);
                if (ops1 != null && ops1.contains("SP")) {
                    movemNoLink++;
                    int regCount = ops0 == null ? 0 : countRegisters(ops0);
                    if (regCount >= 7) savesWide++;
                    else if (regCount > 0) savesNarrow++;
                } else {
                    noProlog++;
                }
            } else {
                noProlog++;
            }

            // Check for PC-relative global access in first few instructions
            for (int i = 0; i < 8 && instr != null; i++) {
                String mn = instr.getMnemonicString().toLowerCase();
                if (mn.equals("lea")) {
                    String op0 = instr.getDefaultOperandRepresentation(0);
                    if (op0 != null && op0.contains("PC")) pcRelGlobal++;
                } else if (mn.equals("movea.l")) {
                    String op0 = instr.getDefaultOperandRepresentation(0);
                    if (op0 != null && op0.contains(".L") && !op0.contains("PC")) absGlobal++;
                }
                instr = listing.getInstructionAfter(instr.getAddress());
                if (instr == null || !func.getBody().contains(instr.getAddress())) break;
            }
        }

        // --- Verdict ---
        println("═══════════════════════════════════════════════════");
        println(" Amiga Compiler Fingerprint Analysis");
        println("═══════════════════════════════════════════════════");
        println(String.format(" Total functions analyzed : %d", total));
        println(String.format(" LINK A5 prologues        : %d  (SAS/C, Lattice, StormC)", linkA5));
        println(String.format(" LINK A6 prologues        : %d  (GCC -fno-omit-frame-pointer)", linkA6));
        println(String.format(" MOVEM only (no LINK)     : %d  (GCC, VBCC, DICE)", movemNoLink));
        println(String.format(" No standard prologue     : %d  (hand-asm, tiny funcs)", noProlog));
        println(String.format(" Wide reg saves (7+)      : %d  (SAS/C style)", savesWide));
        println(String.format(" Narrow reg saves (<7)    : %d  (Lattice/GCC style)", savesNarrow));
        println(String.format(" PC-relative globals      : %d  (GCC -fpic or VBCC)", pcRelGlobal));
        println(String.format(" Absolute globals         : %d  (SAS/C, GCC without -fpic)", absGlobal));
        println("---------------------------------------------------");
        println(" Symbol table heuristics:");
        println("  _mainCRTStartup : " + hasCRTStartup + "  (DICE C)");
        println("  __main/__exit   : " + hasMainGCC    + "  (GCC/libnix)");
        println("  _c_start        : " + hasCStart     + "  (SAS/C)");
        println("  _ReturnCode     : " + hasReturnCode + "  (SAS/C)");
        println("  __ct__/__dt__   : " + hasCtDt       + "  (StormC C++)");
        println("---------------------------------------------------");
        println(" VERDICT: " + pickVerdict(total, linkA5, linkA6, movemNoLink, noProlog,
            savesWide, savesNarrow, pcRelGlobal, absGlobal,
            hasCRTStartup, hasMainGCC, hasCStart, hasCtDt));
        println("═══════════════════════════════════════════════════");
    }

    private int countRegisters(String regList) {
        // Count comma-separated tokens and register ranges like D2-D7
        int count = 0;
        if (regList == null) return 0;
        for (String tok : regList.split("[,/]")) {
            tok = tok.trim();
            if (tok.matches("[DA]\\d-[DA]\\d")) {
                // Range like D2-D7 or A2-A4
                int lo = tok.charAt(1) - '0';
                int hi = tok.charAt(3) - '0';
                count += Math.abs(hi - lo) + 1;
            } else if (tok.matches("[DA]\\d")) {
                count++;
            }
        }
        return count;
    }

    private String pickVerdict(int total, int linkA5, int linkA6, int movemNoLink, int noProlog,
        int savesWide, int savesNarrow, int pcRelGlobal, int absGlobal,
        boolean hasCRTStartup, boolean hasMainGCC, boolean hasCStart, boolean hasCtDt) {

        if (total == 0) return "No functions to analyze.";

        // Strong symbol-based signals
        if (hasCRTStartup && linkA5 == 0 && linkA6 == 0) return "DICE C (high confidence: _mainCRTStartup found)";
        if (hasCtDt) return "StormC C++ (high confidence: C++ name mangling found)";
        if (hasCStart && linkA5 > 0) return "SAS/C 6.x (high confidence: _c_start + LINK A5)";
        if (hasMainGCC) {
            if (linkA6 > linkA5) return "GCC m68k with frame pointer (high confidence: __main + LINK A6)";
            return "GCC m68k / libnix (high confidence: __main found)";
        }

        // Prologue-based majority vote
        int dominant = Math.max(linkA5, Math.max(linkA6, movemNoLink));
        if (dominant == 0) return "Hand-written assembly (no standard prologues detected)";

        double linkA5Pct  = 100.0 * linkA5 / total;
        double linkA6Pct  = 100.0 * linkA6 / total;
        double movemPct   = 100.0 * movemNoLink / total;

        if (linkA5 == dominant) {
            if (savesWide > savesNarrow) return String.format("SAS/C 6.x (%.0f%% LINK A5, wide register saves)", linkA5Pct);
            if (savesNarrow > savesWide) return String.format("Lattice C 3/4 (%.0f%% LINK A5, narrow register saves)", linkA5Pct);
            return String.format("SAS/C or Lattice C (%.0f%% LINK A5)", linkA5Pct);
        }
        if (linkA6 == dominant) {
            return String.format("GCC m68k with -fno-omit-frame-pointer (%.0f%% LINK A6)", linkA6Pct);
        }
        if (movemNoLink == dominant) {
            if (pcRelGlobal > absGlobal) return String.format("GCC -fpic or VBCC (%.0f%% MOVEM, PC-relative globals)", movemPct);
            if (absGlobal > pcRelGlobal) return String.format("GCC without -fpic (%.0f%% MOVEM, absolute globals)", movemPct);
            return String.format("GCC / VBCC / DICE C (%.0f%% MOVEM only prologues)", movemPct);
        }
        if (noProlog > linkA5 + linkA6 + movemNoLink) {
            return "Likely hand-written assembly (majority of functions have no standard prologue)";
        }
        return "Mixed / unknown toolchain — check individual function prologues.";
    }
}
