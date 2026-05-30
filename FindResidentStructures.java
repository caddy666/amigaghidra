// Scans all memory blocks for Resident structure markers ($4AFC = RTC_MATCHWORD)
// and adds detailed plate comments describing each field.
// The hunk loader already applies the Resident data type; this script adds human-
// readable plate comments and EOL annotations for each confirmed Resident so you can
// read the structure fields directly in the listing without opening the struct editor.
// Also useful as a post-load re-scan for Kickstart ROMs or binaries with embedded libraries.
//@author AmigaGhidra
//@category Amiga
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.SourceType;

public class FindResidentStructures extends GhidraScript {

    // exec/resident.h field offsets
    static final int RT_MATCHWORD  = 0x00; // UWORD $4AFC
    static final int RT_MATCHTAG   = 0x02; // APTR — pointer back to self
    static final int RT_ENDSKIP    = 0x06; // APTR — address after this structure
    static final int RT_FLAGS      = 0x0A; // UBYTE
    static final int RT_VERSION    = 0x0B; // UBYTE
    static final int RT_TYPE       = 0x0C; // UBYTE — NT_LIBRARY=9, NT_DEVICE=3
    static final int RT_PRI        = 0x0D; // BYTE — init priority
    static final int RT_NAME       = 0x0E; // APTR → name string
    static final int RT_IDSTRING   = 0x12; // APTR → id/version string
    static final int RT_INIT       = 0x16; // APTR → init function or AutoInit table

    static final int STRUCT_SIZE   = 0x1A; // sizeof(struct Resident) = 26 bytes

    // RTF flag bits
    static final int RTF_AUTOINIT  = 0x80;
    static final int RTF_AFTERDOS  = 0x04;
    static final int RTF_SINGLETASK= 0x02;
    static final int RTF_COLDSTART = 0x01;

    @Override
    protected void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        byte[] matchWord = { 0x4A, (byte) 0xFC };

        int found = 0;
        Address scanFrom = currentProgram.getMinAddress();

        while (!monitor.isCancelled()) {
            Address hit = find(scanFrom, matchWord);
            if (hit == null) break;
            scanFrom = hit.add(2);

            // Validate: the LONG at +2 must point back to this exact address
            try {
                long matchtag = mem.getInt(hit.add(2), false) & 0xFFFFFFFFL;
                if (matchtag != (hit.getOffset() & 0xFFFFFFFFL)) {
                    continue; // false positive
                }
            } catch (Exception e) {
                continue;
            }

            found++;
            annotateResident(mem, hit);
        }

        println("Found and annotated " + found + " Resident structure(s).");
        if (found == 0) {
            println("  (No $4AFC markers with valid self-pointer found)");
        }
    }

    private void annotateResident(Memory mem, Address base) throws Exception {
        try {
            short flags   = mem.getByte(base.add(RT_FLAGS));
            short version = (short)(mem.getByte(base.add(RT_VERSION)) & 0xFF);
            short type    = (short)(mem.getByte(base.add(RT_TYPE)) & 0xFF);
            byte  pri     = mem.getByte(base.add(RT_PRI));
            long  namePtr = mem.getInt(base.add(RT_NAME), false) & 0xFFFFFFFFL;
            long  idPtr   = mem.getInt(base.add(RT_IDSTRING), false) & 0xFFFFFFFFL;
            long  initPtr = mem.getInt(base.add(RT_INIT), false) & 0xFFFFFFFFL;
            long  endskip = mem.getInt(base.add(RT_ENDSKIP), false) & 0xFFFFFFFFL;

            String name   = readString(mem, base.getNewAddress(namePtr));
            String idStr  = readString(mem, base.getNewAddress(idPtr));
            String typeStr = decodeType(type);
            String flagStr = decodeFlags(flags & 0xFF);

            // Create a label for the resident
            String labelName = "Resident_" + sanitize(name);
            try {
                currentProgram.getSymbolTable().createLabel(base, labelName, SourceType.USER_DEFINED);
            } catch (Exception e) { /* may already exist */ }

            // Set plate comment with full struct decode
            String plate = String.format(
                "struct Resident @ 0x%08X\n" +
                "  rt_MatchWord  = $4AFC\n" +
                "  rt_MatchTag   = 0x%08X (self)\n" +
                "  rt_EndSkip    = 0x%08X\n" +
                "  rt_Flags      = 0x%02X  [%s]\n" +
                "  rt_Version    = %d\n" +
                "  rt_Type       = %d  (%s)\n" +
                "  rt_Pri        = %d\n" +
                "  rt_Name       = \"%s\"\n" +
                "  rt_IdString   = \"%s\"\n" +
                "  rt_Init       = 0x%08X  [%s]",
                base.getOffset(),
                base.getOffset(),
                endskip,
                flags & 0xFF, flagStr,
                version,
                type, typeStr,
                pri,
                name,
                idStr,
                initPtr,
                ((flags & RTF_AUTOINIT) != 0) ? "AutoInit table pointer" : "LibInit function"
            );
            setPlateComment(base, plate);

            // Label field addresses for quick navigation
            setEOLComment(base.add(RT_FLAGS),   "rt_Flags: " + flagStr);
            setEOLComment(base.add(RT_VERSION), "rt_Version: " + version);
            setEOLComment(base.add(RT_TYPE),    "rt_Type: " + typeStr);
            setEOLComment(base.add(RT_PRI),     "rt_Pri: " + pri);
            setEOLComment(base.add(RT_NAME),    "rt_Name -> \"" + name + "\"");
            setEOLComment(base.add(RT_IDSTRING),"rt_IdString -> \"" + idStr + "\"");
            setEOLComment(base.add(RT_INIT),    "rt_Init -> " + ((flags & RTF_AUTOINIT) != 0 ? "AutoInit[]" : "LibInit()"));

            // Label the init target
            if (initPtr != 0 && initPtr != 0xFFFFFFFFL) {
                Address initAddr = base.getNewAddress(initPtr);
                if (currentProgram.getMemory().contains(initAddr)) {
                    String initLabel = ((flags & RTF_AUTOINIT) != 0) ?
                        "AutoInitTable_" + sanitize(name) : "LibInit_" + sanitize(name);
                    try {
                        currentProgram.getSymbolTable().createLabel(initAddr, initLabel, SourceType.USER_DEFINED);
                    } catch (Exception e) { /* already labeled */ }
                }
            }

            println(String.format("  Resident: \"%s\" v%d pri=%d @ 0x%08X", name, version, pri, base.getOffset()));

        } catch (Exception e) {
            println("  Warning: could not fully decode Resident at 0x" + base.toString() + ": " + e.getMessage());
        }
    }

    private String readString(Memory mem, Address addr) {
        if (addr == null || !mem.contains(addr)) return "<invalid ptr>";
        StringBuilder sb = new StringBuilder();
        try {
            for (int i = 0; i < 256; i++) {
                byte b = mem.getByte(addr.add(i));
                if (b == 0 || b == '\r' || b == '\n') break;
                sb.append((char)(b & 0xFF));
            }
        } catch (Exception e) { /* truncate */ }
        return sb.toString();
    }

    private String decodeType(int type) {
        switch (type) {
            case 0x01: return "NT_TASK";
            case 0x02: return "NT_INTERRUPT";
            case 0x03: return "NT_DEVICE";
            case 0x04: return "NT_MSGPORT";
            case 0x05: return "NT_MESSAGE";
            case 0x06: return "NT_FREEMSG";
            case 0x07: return "NT_REPLYMSG";
            case 0x08: return "NT_RESOURCE";
            case 0x09: return "NT_LIBRARY";
            case 0x0A: return "NT_MEMORY";
            case 0x0B: return "NT_SOFTINT";
            case 0x0C: return "NT_FONT";
            case 0x0D: return "NT_PROCESS";
            case 0x0E: return "NT_SEMAPHORE";
            case 0x0F: return "NT_SIGNALSEM";
            case 0x10: return "NT_BOOTNODE";
            case 0x11: return "NT_KICKMEM";
            case 0x12: return "NT_GRAPHICS";
            case 0x13: return "NT_DEATHMESSAGE";
            default:   return String.format("NT_%02X", type);
        }
    }

    private String decodeFlags(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & RTF_AUTOINIT)   != 0) sb.append("AUTOINIT|");
        if ((flags & RTF_AFTERDOS)   != 0) sb.append("AFTERDOS|");
        if ((flags & RTF_SINGLETASK) != 0) sb.append("SINGLETASK|");
        if ((flags & RTF_COLDSTART)  != 0) sb.append("COLDSTART|");
        String s = sb.toString();
        return s.isEmpty() ? "0" : s.substring(0, s.length() - 1);
    }

    private String sanitize(String s) {
        return s.replaceAll("[^A-Za-z0-9_]", "_");
    }
}
