// Maps all ECS (Enhanced Chip Set) custom chip registers to named labels.
// Includes all OCS registers plus ECS-specific additions (BEAMCON0, HTOTAL, DENISEID,
// BLTCON0L, BLTSIZV/H, SPRHDAT, STREQU/STRVBL/STRHOR/STRLONG, DIWHIGH, HSSTRT/VSSTRT).
// Run this for A500+, A600, A2000 rev6+, A3000 (ECS machines).
// Safe to run multiple times — skips existing blocks and labels.
//@author AmigaGhidra
//@category Amiga
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.SourceType;

public class MapHardwareRegisters_ECS extends GhidraScript {

    private int labeled = 0;

    @Override
    protected void run() throws Exception {
        ensureBlock("HW_CUSTOM", 0xDFF000L, 0x200);
        ensureBlock("HW_CIAA",   0xBFE000L, 0x1000);
        ensureBlock("HW_CIAB",   0xBFD000L, 0x1000);

        mapCustom();
        mapCIAA();
        mapCIAB();

        println("ECS: labeled " + labeled + " hardware registers.");
    }

    private void mapCustom() throws Exception {
        long base = 0xDFF000L;
        // Read-only / strobe registers (OCS + ECS additions)
        word(base + 0x000, "BLTDDAT");
        word(base + 0x002, "DMACONR");
        word(base + 0x004, "VPOSR");
        word(base + 0x006, "VHPOSR");
        word(base + 0x008, "DSKDATR");
        word(base + 0x00A, "JOY0DAT");
        word(base + 0x00C, "JOY1DAT");
        word(base + 0x00E, "CLXDAT");
        word(base + 0x010, "ADKCONR");
        word(base + 0x012, "POT0DAT");
        word(base + 0x014, "POT1DAT");
        word(base + 0x016, "POTGOR");
        word(base + 0x018, "SERDATR");
        word(base + 0x01A, "DSKBYTR");
        word(base + 0x01C, "INTENAR");
        word(base + 0x01E, "INTREQR");
        word(base + 0x020, "DSKPTH");
        word(base + 0x022, "DSKPTL");
        word(base + 0x024, "DSKLEN");
        word(base + 0x026, "DSKDAT");
        word(base + 0x028, "REFPTR");
        word(base + 0x02A, "VPOSW");
        word(base + 0x02C, "VHPOSW");
        word(base + 0x02E, "COPCON");
        word(base + 0x030, "SERDAT");
        word(base + 0x032, "SERPER");
        word(base + 0x034, "POTGO");
        word(base + 0x036, "JOYTEST");
        // ECS-only strobe registers for genlock sync
        word(base + 0x038, "STREQU");    // Strobe for horizontal sync with HSYNC
        word(base + 0x03A, "STRVBL");    // Strobe for vertical blanking
        word(base + 0x03C, "STRHOR");    // Strobe for horizontal sync
        word(base + 0x03E, "STRLONG");   // Strobe for long line toggle
        // Blitter
        word(base + 0x040, "BLTCON0");
        word(base + 0x042, "BLTCON1");
        word(base + 0x044, "BLTAFWM");
        word(base + 0x046, "BLTALWM");
        word(base + 0x048, "BLTCPTH");
        word(base + 0x04A, "BLTCPTL");
        word(base + 0x04C, "BLTBPTH");
        word(base + 0x04E, "BLTBPTL");
        word(base + 0x050, "BLTAPTH");
        word(base + 0x052, "BLTAPTL");
        word(base + 0x054, "BLTDPTH");
        word(base + 0x056, "BLTDPTL");
        word(base + 0x058, "BLTSIZE");
        word(base + 0x05A, "BLTCON0L"); // ECS: blitter control 0 low byte
        word(base + 0x05C, "BLTSIZV");  // ECS: blitter size vertical
        word(base + 0x05E, "BLTSIZH");  // ECS: blitter size horizontal + start
        word(base + 0x060, "BLTCMOD");
        word(base + 0x062, "BLTBMOD");
        word(base + 0x064, "BLTAMOD");
        word(base + 0x066, "BLTDMOD");
        word(base + 0x070, "BLTCDAT");
        word(base + 0x072, "BLTBDAT");
        word(base + 0x074, "BLTADAT");
        word(base + 0x078, "SPRHDAT");  // ECS: sprite high data (upper bitplane)
        word(base + 0x07C, "DENISEID"); // ECS: Denise revision ID register
        word(base + 0x07E, "DSKSYNC");
        // Copper
        word(base + 0x080, "COP1LCH");
        word(base + 0x082, "COP1LCL");
        word(base + 0x084, "COP2LCH");
        word(base + 0x086, "COP2LCL");
        word(base + 0x088, "COPJMP1");
        word(base + 0x08A, "COPJMP2");
        word(base + 0x08C, "COPINS");
        word(base + 0x08E, "DIWSTRT");
        word(base + 0x090, "DIWSTOP");
        word(base + 0x092, "DDFSTRT");
        word(base + 0x094, "DDFSTOP");
        word(base + 0x096, "DMACON");
        word(base + 0x098, "CLXCON");
        word(base + 0x09A, "INTENA");
        word(base + 0x09C, "INTREQ");
        word(base + 0x09E, "ADKCON");
        // Audio
        word(base + 0x0A0, "AUD0LCH"); word(base + 0x0A2, "AUD0LCL");
        word(base + 0x0A4, "AUD0LEN"); word(base + 0x0A6, "AUD0PER");
        word(base + 0x0A8, "AUD0VOL"); word(base + 0x0AA, "AUD0DAT");
        word(base + 0x0B0, "AUD1LCH"); word(base + 0x0B2, "AUD1LCL");
        word(base + 0x0B4, "AUD1LEN"); word(base + 0x0B6, "AUD1PER");
        word(base + 0x0B8, "AUD1VOL"); word(base + 0x0BA, "AUD1DAT");
        word(base + 0x0C0, "AUD2LCH"); word(base + 0x0C2, "AUD2LCL");
        word(base + 0x0C4, "AUD2LEN"); word(base + 0x0C6, "AUD2PER");
        word(base + 0x0C8, "AUD2VOL"); word(base + 0x0CA, "AUD2DAT");
        word(base + 0x0D0, "AUD3LCH"); word(base + 0x0D2, "AUD3LCL");
        word(base + 0x0D4, "AUD3LEN"); word(base + 0x0D6, "AUD3PER");
        word(base + 0x0D8, "AUD3VOL"); word(base + 0x0DA, "AUD3DAT");
        // Bitplane pointers
        word(base + 0x0E0, "BPL1PTH"); word(base + 0x0E2, "BPL1PTL");
        word(base + 0x0E4, "BPL2PTH"); word(base + 0x0E6, "BPL2PTL");
        word(base + 0x0E8, "BPL3PTH"); word(base + 0x0EA, "BPL3PTL");
        word(base + 0x0EC, "BPL4PTH"); word(base + 0x0EE, "BPL4PTL");
        word(base + 0x0F0, "BPL5PTH"); word(base + 0x0F2, "BPL5PTL");
        word(base + 0x0F4, "BPL6PTH"); word(base + 0x0F6, "BPL6PTL");
        word(base + 0x100, "BPLCON0");
        word(base + 0x102, "BPLCON1");
        word(base + 0x104, "BPLCON2");
        word(base + 0x108, "BPL1MOD");
        word(base + 0x10A, "BPL2MOD");
        word(base + 0x110, "BPL1DAT"); word(base + 0x112, "BPL2DAT");
        word(base + 0x114, "BPL3DAT"); word(base + 0x116, "BPL4DAT");
        word(base + 0x118, "BPL5DAT"); word(base + 0x11A, "BPL6DAT");
        // Sprites
        word(base + 0x120, "SPR0PTH"); word(base + 0x122, "SPR0PTL");
        word(base + 0x124, "SPR1PTH"); word(base + 0x126, "SPR1PTL");
        word(base + 0x128, "SPR2PTH"); word(base + 0x12A, "SPR2PTL");
        word(base + 0x12C, "SPR3PTH"); word(base + 0x12E, "SPR3PTL");
        word(base + 0x130, "SPR4PTH"); word(base + 0x132, "SPR4PTL");
        word(base + 0x134, "SPR5PTH"); word(base + 0x136, "SPR5PTL");
        word(base + 0x138, "SPR6PTH"); word(base + 0x13A, "SPR6PTL");
        word(base + 0x13C, "SPR7PTH"); word(base + 0x13E, "SPR7PTL");
        word(base + 0x140, "SPR0POS");  word(base + 0x142, "SPR0CTL");
        word(base + 0x144, "SPR0DATA"); word(base + 0x146, "SPR0DATB");
        word(base + 0x148, "SPR1POS");  word(base + 0x14A, "SPR1CTL");
        word(base + 0x14C, "SPR1DATA"); word(base + 0x14E, "SPR1DATB");
        word(base + 0x150, "SPR2POS");  word(base + 0x152, "SPR2CTL");
        word(base + 0x154, "SPR2DATA"); word(base + 0x156, "SPR2DATB");
        word(base + 0x158, "SPR3POS");  word(base + 0x15A, "SPR3CTL");
        word(base + 0x15C, "SPR3DATA"); word(base + 0x15E, "SPR3DATB");
        word(base + 0x160, "SPR4POS");  word(base + 0x162, "SPR4CTL");
        word(base + 0x164, "SPR4DATA"); word(base + 0x166, "SPR4DATB");
        word(base + 0x168, "SPR5POS");  word(base + 0x16A, "SPR5CTL");
        word(base + 0x16C, "SPR5DATA"); word(base + 0x16E, "SPR5DATB");
        word(base + 0x170, "SPR6POS");  word(base + 0x172, "SPR6CTL");
        word(base + 0x174, "SPR6DATA"); word(base + 0x176, "SPR6DATB");
        word(base + 0x178, "SPR7POS");  word(base + 0x17A, "SPR7CTL");
        word(base + 0x17C, "SPR7DATA"); word(base + 0x17E, "SPR7DATB");
        // Color palette
        for (int i = 0; i < 32; i++) {
            word(base + 0x180 + i * 2, String.format("COLOR%02d", i));
        }
        // ECS display timing registers ($1C0-$1E4)
        word(base + 0x1C0, "HTOTAL");   // Horizontal total (programmable) [ECS]
        word(base + 0x1C2, "HSSTOP");   // Horizontal sync stop [ECS]
        word(base + 0x1C4, "HBSTRT");   // Horizontal blank start [ECS]
        word(base + 0x1C6, "HBSTOP");   // Horizontal blank stop [ECS]
        word(base + 0x1C8, "VTOTAL");   // Vertical total [ECS]
        word(base + 0x1CA, "VSSTOP");   // Vertical sync stop [ECS]
        word(base + 0x1CC, "VBSTRT");   // Vertical blank start [ECS]
        word(base + 0x1CE, "VBSTOP");   // Vertical blank stop [ECS]
        word(base + 0x1DC, "BEAMCON0"); // Beam control register [ECS]
        word(base + 0x1DE, "HSSTRT");   // Horizontal sync start [ECS]
        word(base + 0x1E0, "VSSTRT");   // Vertical sync start [ECS]
        word(base + 0x1E2, "HCENTER");  // Horizontal position of VSYNC [ECS]
        word(base + 0x1E4, "DIWHIGH");  // Display window upper bits [ECS]
    }

    private void mapCIAA() throws Exception {
        long base = 0xBFE000L;
        abyte(base + 0x001, "CIAA_PRA");
        abyte(base + 0x101, "CIAA_PRB");
        abyte(base + 0x201, "CIAA_DDRA");
        abyte(base + 0x301, "CIAA_DDRB");
        abyte(base + 0x401, "CIAA_TALO");
        abyte(base + 0x501, "CIAA_TAHI");
        abyte(base + 0x601, "CIAA_TBLO");
        abyte(base + 0x701, "CIAA_TBHI");
        abyte(base + 0x801, "CIAA_TODLO");
        abyte(base + 0x901, "CIAA_TODMID");
        abyte(base + 0xA01, "CIAA_TODHI");
        abyte(base + 0xB01, "CIAA_SDR");
        abyte(base + 0xC01, "CIAA_ICR");
        abyte(base + 0xD01, "CIAA_CRA");
        abyte(base + 0xE01, "CIAA_CRB");
    }

    private void mapCIAB() throws Exception {
        long base = 0xBFD000L;
        abyte(base + 0x000, "CIAB_PRA");
        abyte(base + 0x100, "CIAB_PRB");
        abyte(base + 0x200, "CIAB_DDRA");
        abyte(base + 0x300, "CIAB_DDRB");
        abyte(base + 0x400, "CIAB_TALO");
        abyte(base + 0x500, "CIAB_TAHI");
        abyte(base + 0x600, "CIAB_TBLO");
        abyte(base + 0x700, "CIAB_TBHI");
        abyte(base + 0x800, "CIAB_TODLO");
        abyte(base + 0x900, "CIAB_TODMID");
        abyte(base + 0xA00, "CIAB_TODHI");
        abyte(base + 0xB00, "CIAB_SDR");
        abyte(base + 0xC00, "CIAB_ICR");
        abyte(base + 0xD00, "CIAB_CRA");
        abyte(base + 0xE00, "CIAB_CRB");
    }

    private void ensureBlock(String name, long baseAddr, long size) throws Exception {
        Memory mem = currentProgram.getMemory();
        if (mem.getBlock(name) != null) {
            println(name + " block already exists.");
            return;
        }
        Address start = toAddr(baseAddr);
        mem.createUninitializedBlock(name, start, size, false);
        MemoryBlock block = mem.getBlock(name);
        block.setRead(true);
        block.setWrite(true);
        block.setExecute(false);
        block.setVolatile(true);
        println("Created " + name + " at 0x" + Long.toHexString(baseAddr).toUpperCase());
    }

    private void word(long addr, String name) throws Exception {
        Address a = toAddr(addr);
        try { createWord(a); } catch (Exception e) { /* already defined */ }
        try {
            currentProgram.getSymbolTable().createLabel(a, name, SourceType.USER_DEFINED);
            labeled++;
        } catch (Exception e) { /* already labeled */ }
    }

    private void abyte(long addr, String name) throws Exception {
        Address a = toAddr(addr);
        try { createByte(a); } catch (Exception e) { /* already defined */ }
        try {
            currentProgram.getSymbolTable().createLabel(a, name, SourceType.USER_DEFINED);
            labeled++;
        } catch (Exception e) { /* already labeled */ }
    }
}
