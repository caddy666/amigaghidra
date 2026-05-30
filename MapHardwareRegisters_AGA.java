// Maps all AGA (Advanced Graphics Architecture) custom chip registers to named labels.
// Includes all OCS+ECS registers plus AGA-specific additions:
//   BPLCON3 ($106), BPLCON4 ($10C), CLXCON2 ($10E), BPLHMOD ($1E6),
//   SPRHSTRT/SPRHSTOP/BPLHSTRT/BPLHSTOP ($1D0-$1D6),
//   SPRHPT high/low ($1E4/$1E6), BPLHPT high/low ($1E8/$1EA),
//   BPLHDAT ($1EC), FMODE ($1FC).
// Run this for A1200, A4000, CD32 (AGA machines).
//@author AmigaGhidra
//@category Amiga
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.SourceType;

public class MapHardwareRegisters_AGA extends GhidraScript {

    private int labeled = 0;

    @Override
    protected void run() throws Exception {
        ensureBlock("HW_CUSTOM", 0xDFF000L, 0x200);
        ensureBlock("HW_CIAA",   0xBFE000L, 0x1000);
        ensureBlock("HW_CIAB",   0xBFD000L, 0x1000);

        mapCustom();
        mapCIAA();
        mapCIAB();

        println("AGA: labeled " + labeled + " hardware registers.");
    }

    private void mapCustom() throws Exception {
        long base = 0xDFF000L;
        // Full OCS+ECS+AGA register set
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
        word(base + 0x038, "STREQU");
        word(base + 0x03A, "STRVBL");
        word(base + 0x03C, "STRHOR");
        word(base + 0x03E, "STRLONG");
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
        word(base + 0x05A, "BLTCON0L");
        word(base + 0x05C, "BLTSIZV");
        word(base + 0x05E, "BLTSIZH");
        word(base + 0x060, "BLTCMOD");
        word(base + 0x062, "BLTBMOD");
        word(base + 0x064, "BLTAMOD");
        word(base + 0x066, "BLTDMOD");
        word(base + 0x070, "BLTCDAT");
        word(base + 0x072, "BLTBDAT");
        word(base + 0x074, "BLTADAT");
        word(base + 0x078, "SPRHDAT");   // ECS/AGA: sprite high data
        word(base + 0x07A, "BPLHDAT");   // AGA: bitplane high data
        word(base + 0x07C, "DENISEID");
        word(base + 0x07E, "DSKSYNC");
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
        word(base + 0x0F8, "BPL7PTH"); word(base + 0x0FA, "BPL7PTL"); // AGA planes 7-8
        word(base + 0x0FC, "BPL8PTH"); word(base + 0x0FE, "BPL8PTL");
        // Bitplane control — AGA adds BPLCON3 and BPLCON4
        word(base + 0x100, "BPLCON0");
        word(base + 0x102, "BPLCON1");
        word(base + 0x104, "BPLCON2");
        word(base + 0x106, "BPLCON3");  // AGA: bitplane control 3 (bank select, border blank)
        word(base + 0x108, "BPL1MOD");
        word(base + 0x10A, "BPL2MOD");
        word(base + 0x10C, "BPLCON4");  // AGA: bitplane control 4 (XOR mask, palette bank)
        word(base + 0x10E, "CLXCON2"); // AGA: extended collision control
        // Bitplane data registers (AGA has 8 planes)
        word(base + 0x110, "BPL1DAT"); word(base + 0x112, "BPL2DAT");
        word(base + 0x114, "BPL3DAT"); word(base + 0x116, "BPL4DAT");
        word(base + 0x118, "BPL5DAT"); word(base + 0x11A, "BPL6DAT");
        word(base + 0x11C, "BPL7DAT"); word(base + 0x11E, "BPL8DAT");
        // Sprite pointers
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
        // Color registers (AGA still uses 32 entries via BPLCON3 bank select)
        for (int i = 0; i < 32; i++) {
            word(base + 0x180 + i * 2, String.format("COLOR%02d", i));
        }
        // ECS display timing
        word(base + 0x1C0, "HTOTAL");
        word(base + 0x1C2, "HSSTOP");
        word(base + 0x1C4, "HBSTRT");
        word(base + 0x1C6, "HBSTOP");
        word(base + 0x1C8, "VTOTAL");
        word(base + 0x1CA, "VSSTOP");
        word(base + 0x1CC, "VBSTRT");
        word(base + 0x1CE, "VBSTOP");
        // AGA-only: sprite/bitplane high data fetch timing
        word(base + 0x1D0, "SPRHSTRT"); // AGA: sprite high-res fetch start
        word(base + 0x1D2, "SPRHSTOP"); // AGA: sprite high-res fetch stop
        word(base + 0x1D4, "BPLHSTRT"); // AGA: bitplane high-res fetch start
        word(base + 0x1D6, "BPLHSTOP"); // AGA: bitplane high-res fetch stop
        word(base + 0x1D8, "HHPOSW");   // AGA: dual-playfield horizontal scroll write
        word(base + 0x1DA, "HHPOSR");   // AGA: dual-playfield horizontal scroll read
        word(base + 0x1DC, "BEAMCON0");
        word(base + 0x1DE, "HSSTRT");
        word(base + 0x1E0, "VSSTRT");
        word(base + 0x1E2, "HCENTER");
        word(base + 0x1E4, "DIWHIGH");
        word(base + 0x1E6, "BPLHMOD");  // AGA: bitplane high-res modulo
        word(base + 0x1E8, "SPRHPTH");  // AGA: sprite high-res pointer (high)
        word(base + 0x1EA, "SPRHPTL");  // AGA: sprite high-res pointer (low)
        word(base + 0x1EC, "BPLHPTH");  // AGA: bitplane high-res pointer (high)
        word(base + 0x1EE, "BPLHPTL");  // AGA: bitplane high-res pointer (low)
        word(base + 0x1FC, "FMODE");    // AGA: fetch mode control (32/64-bit bus)
    }

    private void mapCIAA() throws Exception {
        long base = 0xBFE000L;
        abyte(base + 0x001, "CIAA_PRA");    abyte(base + 0x101, "CIAA_PRB");
        abyte(base + 0x201, "CIAA_DDRA");   abyte(base + 0x301, "CIAA_DDRB");
        abyte(base + 0x401, "CIAA_TALO");   abyte(base + 0x501, "CIAA_TAHI");
        abyte(base + 0x601, "CIAA_TBLO");   abyte(base + 0x701, "CIAA_TBHI");
        abyte(base + 0x801, "CIAA_TODLO");  abyte(base + 0x901, "CIAA_TODMID");
        abyte(base + 0xA01, "CIAA_TODHI");  abyte(base + 0xB01, "CIAA_SDR");
        abyte(base + 0xC01, "CIAA_ICR");    abyte(base + 0xD01, "CIAA_CRA");
        abyte(base + 0xE01, "CIAA_CRB");
    }

    private void mapCIAB() throws Exception {
        long base = 0xBFD000L;
        abyte(base + 0x000, "CIAB_PRA");    abyte(base + 0x100, "CIAB_PRB");
        abyte(base + 0x200, "CIAB_DDRA");   abyte(base + 0x300, "CIAB_DDRB");
        abyte(base + 0x400, "CIAB_TALO");   abyte(base + 0x500, "CIAB_TAHI");
        abyte(base + 0x600, "CIAB_TBLO");   abyte(base + 0x700, "CIAB_TBHI");
        abyte(base + 0x800, "CIAB_TODLO");  abyte(base + 0x900, "CIAB_TODMID");
        abyte(base + 0xA00, "CIAB_TODHI");  abyte(base + 0xB00, "CIAB_SDR");
        abyte(base + 0xC00, "CIAB_ICR");    abyte(base + 0xD00, "CIAB_CRA");
        abyte(base + 0xE00, "CIAB_CRB");
    }

    private void ensureBlock(String name, long baseAddr, long size) throws Exception {
        Memory mem = currentProgram.getMemory();
        if (mem.getBlock(name) != null) {
            println(name + " block already exists.");
            return;
        }
        mem.createUninitializedBlock(name, toAddr(baseAddr), size, false);
        MemoryBlock block = mem.getBlock(name);
        block.setRead(true); block.setWrite(true);
        block.setExecute(false); block.setVolatile(true);
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
