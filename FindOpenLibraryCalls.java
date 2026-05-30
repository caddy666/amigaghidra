// Finds all OpenLibrary/CloseLibrary call sites and annotates them with
// plate comments showing the library name and requested version.
// The hunk analyzer resolves which library function is called but does not
// extract the string argument from nearby instructions. This script walks
// backward from each JSR (-552,A6) to find the LEA/MOVEA that loads A1,
// extracts the string, and adds a plate comment:
//   "OpenLibrary("dos.library", 36)"
//
// Also finds:
//   JSR (-414,A6) = CloseLibrary
//   JSR (-552,Ax) for any An where MOVEA.L 4.W,Ax precedes it (exec base idiom)
//   The MOVEA.L D0,addr instruction after OpenLibrary (library base store)
//
// Run after initial analysis to get human-readable OS call annotations.
//@author AmigaGhidra
//@category Amiga
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;

import java.util.*;

public class FindOpenLibraryCalls extends GhidraScript {

    // exec.library LVOs needed for this analysis
    static final int LVO_OPENLIBRARY   = -552; // OpenLibrary(libName/A1, version/D0)
    static final int LVO_CLOSELIBRARY  = -414; // CloseLibrary(library/A1)
    static final int LVO_OLDOPENLIBRARY= -408; // OldOpenLibrary(libName/A1) — V33

    @Override
    protected void run() throws Exception {
        Listing listing = currentProgram.getListing();
        Memory mem = currentProgram.getMemory();

        int openCount = 0;
        int closeCount = 0;
        Map<String, Integer> libUsage = new LinkedHashMap<>();

        InstructionIterator ii = listing.getInstructions(true);
        while (ii.hasNext() && !monitor.isCancelled()) {
            Instruction instr = ii.next();
            String mnem = instr.getMnemonicString().toLowerCase();

            if (!mnem.equals("jsr") && !mnem.equals("jmp")) continue;

            // Check for displacement-based call: JSR (-N,Ax)
            Object[] objs = instr.getOpObjects(0);
            if (objs.length < 1) continue;

            // The displacement is obj[0] (Scalar) and register is obj[1]
            Scalar displacement = null;
            for (Object o : objs) {
                if (o instanceof Scalar) { displacement = (Scalar) o; break; }
            }
            if (displacement == null) continue;

            int lvo = (int) displacement.getSignedValue();
            if (lvo >= 0) continue; // LVOs are always negative

            if (lvo == LVO_OPENLIBRARY || lvo == LVO_OLDOPENLIBRARY) {
                // Walk backward to find library name in A1 and version in D0
                String libName = findLibNameArg(listing, mem, instr);
                int version = findVersionArg(listing, instr);

                String comment;
                if (lvo == LVO_OLDOPENLIBRARY) {
                    comment = String.format("OldOpenLibrary(\"%s\")  [no version check]", libName);
                } else {
                    comment = String.format("OpenLibrary(\"%s\", %d)", libName, version);
                }

                try { setPlateComment(instr.getAddress(), comment); } catch (Exception e) { /* ok */ }

                // Find the library base store: MOVEA.L D0,<global> or MOVE.L D0,addr
                annotateLibBaseStore(listing, instr, libName);

                openCount++;
                if (!libName.isEmpty() && !libName.equals("?")) {
                    libUsage.merge(libName, 1, Integer::sum);
                }

            } else if (lvo == LVO_CLOSELIBRARY) {
                try {
                    setPlateComment(instr.getAddress(), "CloseLibrary(A1)");
                } catch (Exception e) { /* ok */ }
                closeCount++;
            }
        }

        println("OpenLibrary calls found:  " + openCount);
        println("CloseLibrary calls found: " + closeCount);
        println("\nLibrary usage counts:");
        for (Map.Entry<String, Integer> e : libUsage.entrySet()) {
            println(String.format("  %-30s  %d open(s)", e.getKey(), e.getValue()));
        }
    }

    private String findLibNameArg(Listing listing, Memory mem, Instruction jsrInstr) {
        // Walk backward up to 12 instructions looking for MOVEA.L / LEA that loads A1
        Instruction cur = jsrInstr;
        for (int i = 0; i < 12; i++) {
            cur = listing.getInstructionBefore(cur.getAddress());
            if (cur == null) break;
            String mnem = cur.getMnemonicString().toLowerCase();

            // LEA str(PC),A1  or  MOVEA.L #abs,A1
            if (mnem.equals("lea") || mnem.equals("movea.l") || mnem.equals("move.l")) {
                String op1 = cur.getDefaultOperandRepresentation(1);
                if (op1 != null && (op1.equalsIgnoreCase("A1") || op1.equalsIgnoreCase("a1"))) {
                    // Extract string from operand 0 address
                    Object[] objs = cur.getOpObjects(0);
                    for (Object o : objs) {
                        if (o instanceof Address) {
                            return readString(mem, (Address) o);
                        } else if (o instanceof ghidra.program.model.address.Address) {
                            return readString(mem, (ghidra.program.model.address.Address) o);
                        }
                    }
                    // Try to get referenced address
                    Address refTarget = getFirstReference(cur);
                    if (refTarget != null) return readString(mem, refTarget);
                }
            }
        }
        return "?";
    }

    private int findVersionArg(Listing listing, Instruction jsrInstr) {
        // Walk backward looking for MOVE.L #N,D0 or MOVEQ #N,D0
        Instruction cur = jsrInstr;
        for (int i = 0; i < 12; i++) {
            cur = listing.getInstructionBefore(cur.getAddress());
            if (cur == null) break;
            String mnem = cur.getMnemonicString().toLowerCase();
            if (mnem.equals("moveq") || mnem.equals("move.l") || mnem.equals("move.w")) {
                String op1 = cur.getDefaultOperandRepresentation(1);
                if (op1 != null && (op1.equalsIgnoreCase("D0") || op1.equalsIgnoreCase("d0"))) {
                    Object[] objs = cur.getOpObjects(0);
                    for (Object o : objs) {
                        if (o instanceof Scalar) return (int) ((Scalar) o).getValue();
                    }
                }
            }
        }
        return 0;
    }

    private void annotateLibBaseStore(Listing listing, Instruction jsrInstr, String libName) throws Exception {
        if (libName == null || libName.isEmpty() || libName.equals("?")) return;

        // Walk forward up to 4 instructions looking for MOVEA.L D0,<global> or MOVE.L D0,addr
        Instruction cur = jsrInstr;
        for (int i = 0; i < 6; i++) {
            cur = listing.getInstructionAfter(cur.getAddress());
            if (cur == null) break;
            String mnem = cur.getMnemonicString().toLowerCase();
            if (mnem.equals("movea.l") || mnem.equals("move.l")) {
                String op0 = cur.getDefaultOperandRepresentation(0);
                if (op0 != null && op0.equalsIgnoreCase("D0")) {
                    // This is storing the library base
                    String suggestedName = libName.replace(".", "_").replace("-", "_") + "Base";
                    try {
                        setEOLComment(cur.getAddress(), "→ " + suggestedName);
                    } catch (Exception e) { /* ok */ }
                    // Try to label the destination global
                    Address refTarget = getFirstReference(cur);
                    if (refTarget != null && currentProgram.getMemory().contains(refTarget)) {
                        try {
                            currentProgram.getSymbolTable().createLabel(refTarget, "_" + suggestedName, SourceType.USER_DEFINED);
                        } catch (Exception e) { /* may already exist */ }
                    }
                    break;
                }
            }
            // Stop on calls or branches
            if (mnem.startsWith("jsr") || mnem.startsWith("jmp") || mnem.startsWith("bra") || mnem.startsWith("rts")) break;
        }
    }

    private Address getFirstReference(Instruction instr) {
        ghidra.program.model.symbol.Reference[] refs = instr.getReferencesFrom();
        for (ghidra.program.model.symbol.Reference r : refs) {
            if (r.getReferenceType().isData() || r.getReferenceType().isFlow()) {
                return r.getToAddress();
            }
        }
        return null;
    }

    private String readString(Memory mem, Address addr) {
        if (addr == null || !mem.contains(addr)) return "?";
        StringBuilder sb = new StringBuilder();
        try {
            for (int i = 0; i < 64; i++) {
                byte b = mem.getByte(addr.add(i));
                if (b == 0) break;
                sb.append((char)(b & 0xFF));
            }
        } catch (Exception e) { /* truncate */ }
        return sb.length() == 0 ? "?" : sb.toString();
    }
}
