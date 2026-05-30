// Scans a library's JMP table from a user-supplied library base address.
// Reads lib_NegSize from the Library struct, walks backward through the JMP table
// in 6-byte steps, verifies the JMP.L opcode ($4EF9), creates a function at each
// JMP target, and labels both the JMP slot (LVO_minus_N) and its target.
// Annotates mandatory Open/Close/Expunge/Reserved slots automatically.
// The hunk analyzer resolves A6-based calls; this script labels the JMP table itself
// so you can navigate from LVO numbers directly to implementation addresses.
//@author AmigaGhidra
//@category Amiga
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;

public class ScanLibraryJMPTable extends GhidraScript {

    // struct Library offsets
    static final int LIB_NEGSIZE   = 0x10; // UWORD: total JMP table byte count
    static final int LIB_POSSIZE   = 0x12; // UWORD: Library struct + private data size
    static final int LIB_VERSION   = 0x14; // UWORD: major version
    static final int LIB_REVISION  = 0x16; // UWORD: minor revision
    static final int LIB_IDSTRING  = 0x18; // APTR: id string "name.library N.n (date)"

    static final int JMP_OPCODE    = 0x4EF9; // JMP.L opcode

    @Override
    protected void run() throws Exception {
        Address libBase = currentAddress;

        // Allow user to supply base address if not already at one
        Address asked = askAddress("Library Base", "Enter library base address (or press OK to use current address):");
        if (asked != null) libBase = asked;

        Memory mem = currentProgram.getMemory();

        // Validate: read lib_NegSize
        int negSize;
        try {
            negSize = mem.getShort(libBase.add(LIB_NEGSIZE)) & 0xFFFF;
        } catch (Exception e) {
            popup("Cannot read lib_NegSize at 0x" + libBase.toString() +
                  "\nMake sure the cursor is on a valid library base address.");
            return;
        }

        if (negSize == 0 || negSize > 0x10000 || (negSize % 6) != 0) {
            popup("lib_NegSize = " + negSize + " is not a valid JMP table size (must be nonzero, <64KB, multiple of 6).");
            return;
        }

        int numSlots = negSize / 6;

        // Read library info for labeling
        int version = 0, revision = 0;
        String idString = "";
        try {
            version  = mem.getShort(libBase.add(LIB_VERSION))  & 0xFFFF;
            revision = mem.getShort(libBase.add(LIB_REVISION)) & 0xFFFF;
            long idPtr = mem.getInt(libBase.add(LIB_IDSTRING), false) & 0xFFFFFFFFL;
            idString = readString(mem, libBase.getNewAddress(idPtr));
        } catch (Exception e) { /* optional */ }

        println(String.format("Library base: 0x%08X  negSize: %d bytes = %d slots  v%d.%d",
            libBase.getOffset(), negSize, numSlots, version, revision));
        if (!idString.isEmpty()) println("  ID: " + idString);

        setPlateComment(libBase, String.format(
            "Library base\n  lib_NegSize = %d bytes (%d JMP slots)\n" +
            "  lib_Version = %d.%d\n  id: %s",
            negSize, numSlots, version, revision, idString));

        // Mandatory slot names: Open, Close, Expunge, Reserved are always first
        String[] mandatoryNames = {"LIB_OPEN", "LIB_CLOSE", "LIB_EXPUNGE", "LIB_RESERVED"};

        int labeled = 0;
        int badSlots = 0;

        for (int slot = 1; slot <= numSlots; slot++) {
            int lvo = slot * 6;
            Address slotAddr = libBase.subtract(lvo);

            // Verify JMP.L opcode
            short opcode;
            try {
                opcode = mem.getShort(slotAddr);
            } catch (Exception e) {
                println(String.format("  LVO -%d: cannot read memory at 0x%08X", lvo, slotAddr.getOffset()));
                badSlots++;
                continue;
            }

            if ((opcode & 0xFFFF) != JMP_OPCODE) {
                println(String.format("  LVO -%d: unexpected opcode 0x%04X (expected 4EF9 JMP.L)", lvo, opcode & 0xFFFF));
                badSlots++;
                continue;
            }

            // Read JMP target address
            long targetAddr;
            try {
                targetAddr = mem.getInt(slotAddr.add(2), false) & 0xFFFFFFFFL;
            } catch (Exception e) {
                println(String.format("  LVO -%d: cannot read JMP target", lvo));
                badSlots++;
                continue;
            }

            // Label the JMP slot
            String slotName;
            if (slot <= mandatoryNames.length) {
                slotName = mandatoryNames[slot - 1];
            } else {
                slotName = String.format("LVO_minus_%d", lvo);
            }
            try {
                currentProgram.getSymbolTable().createLabel(slotAddr, slotName, SourceType.USER_DEFINED);
                setEOLComment(slotAddr, String.format("LVO -%d → target: 0x%08X", lvo, targetAddr));
            } catch (Exception e) { /* already labeled */ }

            // Create function and label at target
            Address target = toAddr(targetAddr);
            if (currentProgram.getMemory().contains(target)) {
                String implName;
                if (slot <= mandatoryNames.length) {
                    implName = mandatoryNames[slot - 1] + "_impl";
                } else {
                    implName = String.format("LibFunc_LVO_minus_%d", lvo);
                }
                try {
                    disassemble(target);
                    createFunction(target, implName);
                } catch (Exception e) { /* function may already exist */ }
                try {
                    currentProgram.getSymbolTable().createLabel(target, implName, SourceType.USER_DEFINED);
                } catch (Exception e) { /* already labeled */ }
            }

            labeled++;
            println(String.format("  LVO -%3d  %-30s → 0x%08X", lvo, slotName, targetAddr));
        }

        println(String.format("\nProcessed %d slots: %d labeled, %d bad/skipped.", numSlots, labeled, badSlots));
    }

    private String readString(Memory mem, Address addr) {
        if (addr == null || !mem.contains(addr)) return "";
        StringBuilder sb = new StringBuilder();
        try {
            for (int i = 0; i < 128; i++) {
                byte b = mem.getByte(addr.add(i));
                if (b == 0 || b == '\r' || b == '\n') break;
                sb.append((char)(b & 0xFF));
            }
        } catch (Exception e) { /* truncate */ }
        return sb.toString();
    }
}
