// Maps CD32 Akiko chip registers to named labels.
// Akiko is unique to the CD32 game console, mapped at $B80000.
// Provides: Chunky-to-Planar (C2P) conversion, CD-ROM control, NVRAM I2C interface.
// Register map reverse-engineered from WinUAE akiko.cpp and community hardware testing.
// Reading $B80000 on non-CD32 hardware returns bus noise or causes a bus error.
//@author AmigaGhidra
//@category Amiga
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.SourceType;

public class MapAkikoRegisters extends GhidraScript {

    @Override
    protected void run() throws Exception {
        long akikoBase = 0xB80000L;
        long akikoSize = 0x8000L;

        Memory mem = currentProgram.getMemory();
        if (mem.getBlock("HW_AKIKO") == null) {
            mem.createUninitializedBlock("HW_AKIKO", toAddr(akikoBase), akikoSize, false);
            MemoryBlock blk = mem.getBlock("HW_AKIKO");
            blk.setRead(true); blk.setWrite(true);
            blk.setExecute(false); blk.setVolatile(true);
            println("Created HW_AKIKO block at $B80000");
        } else {
            println("HW_AKIKO block already exists.");
        }

        int n = 0;

        // Chip identification
        n += dword(akikoBase + 0x0000, "AKIKO_ID");
        // read: $C0CACAFE = Akiko present; wrap this in an exception handler on non-CD32

        // Interrupt control
        n += word(akikoBase + 0x0004, "AKIKO_INTREQ");   // Interrupt request (CD subcode, C2P done)
        n += word(akikoBase + 0x0008, "AKIKO_INTENA");   // Interrupt enable mask

        // CD-ROM controller
        n += dword(akikoBase + 0x0010, "CDROM_PBXSTAT");  // PIO buffer / status
        n += dword(akikoBase + 0x0014, "CDROM_FLAGS");    // CD-ROM control flags
        n += dword(akikoBase + 0x0018, "CDROM_TXDATA");   // Command transmit (write)
        n += dword(akikoBase + 0x001C, "CDROM_RXDATA");   // Response receive (read)
        n += dword(akikoBase + 0x0020, "CDROM_SUBCDATA"); // Q-channel subcode data

        // NVRAM I2C bit-bang interface (1 KB battery-backed EEPROM)
        n += dword(akikoBase + 0x0024, "NVRAM_CTRL");     // I2C SCL/SDA direction control
        n += dword(akikoBase + 0x0028, "NVRAM_DATA");     // I2C SCL/SDA bit-bang data

        // Chunky-to-Planar (C2P) conversion engine
        // Write 8 longwords of chunky pixels; then read 8 longwords of planar output.
        // Both input and output share the same address ($B80030).
        n += dword(akikoBase + 0x0030, "C2P_IO");
        // Note: write feeds the pipeline; read retrieves planar result.
        // C2P converts 32 chunky pixels (8-bit) → 8 bitplane longwords per call.

        setPlateComment(toAddr(akikoBase + 0x0030),
            "C2P_IO: Write 8 longwords of chunky pixels (4 pixels each = 32 pixels total).\n" +
            "Then read 8 longwords to get 8-bitplane planar output.\n" +
            "No DMA — register-based pipeline. Must write all 8 before reading.");

        println("Akiko: labeled " + n + " registers.");
    }

    private int dword(long addr, String name) throws Exception {
        Address a = toAddr(addr);
        try { createDWord(a); } catch (Exception e) { /* already defined */ }
        try {
            currentProgram.getSymbolTable().createLabel(a, name, SourceType.USER_DEFINED);
            return 1;
        } catch (Exception e) { return 0; }
    }

    private int word(long addr, String name) throws Exception {
        Address a = toAddr(addr);
        try { createWord(a); } catch (Exception e) { /* already defined */ }
        try {
            currentProgram.getSymbolTable().createLabel(a, name, SourceType.USER_DEFINED);
            return 1;
        } catch (Exception e) { return 0; }
    }
}
