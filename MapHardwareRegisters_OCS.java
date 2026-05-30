// Maps all OCS (Original Chip Set) custom chip registers to named labels.
// Creates HW_CUSTOM ($DFF000), HW_CIAA ($BFE000), and HW_CIAB ($BFD000) memory blocks
// if they do not already exist, then creates a named word (custom) or byte (CIA) label
// at every documented hardware register address.
// Run this on any Amiga OCS/ECS/AGA binary — it is safe to run more than once.
//@author AmigaGhidra
//@category Amiga
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.SourceType;

public class MapHardwareRegisters_OCS extends GhidraScript {

    private int labeled = 0;

    @Override
    protected void run() throws Exception {
        ensureBlock("HW_CUSTOM", 0xDFF000L, 0x200);
        ensureBlock("HW_CIAA",   0xBFE000L, 0x1000);
        ensureBlock("HW_CIAB",   0xBFD000L, 0x1000);

        mapCustom();
        mapCIAA();
        mapCIAB();

        println("OCS: labeled " + labeled + " hardware registers.");
    }

    private void mapCustom() throws Exception {
        long base = 0xDFF000L;
        // Read-only / strobe registers
        word(base + 0x000, "BLTDDAT");   // Blitter destination early read
        word(base + 0x002, "DMACONR");   // DMA control read
        word(base + 0x004, "VPOSR");     // Vertical beam position (high)
        word(base + 0x006, "VHPOSR");    // Vertical/horizontal beam position
        word(base + 0x008, "DSKDATR");   // Disk data early read
        word(base + 0x00A, "JOY0DAT");   // Joystick/mouse 0 data
        word(base + 0x00C, "JOY1DAT");   // Joystick/mouse 1 data
        word(base + 0x00E, "CLXDAT");    // Sprite/playfield collision data
        word(base + 0x010, "ADKCONR");   // Audio/disk/UART control read
        word(base + 0x012, "POT0DAT");   // Pot counter data (port 0)
        word(base + 0x014, "POT1DAT");   // Pot counter data (port 1)
        word(base + 0x016, "POTGOR");    // Pot port data read
        word(base + 0x018, "SERDATR");   // Serial data read
        word(base + 0x01A, "DSKBYTR");   // Disk data byte and status read
        word(base + 0x01C, "INTENAR");   // Interrupt enable bits read
        word(base + 0x01E, "INTREQR");   // Interrupt request bits read
        // Disk DMA
        word(base + 0x020, "DSKPTH");    // Disk pointer (high)
        word(base + 0x022, "DSKPTL");    // Disk pointer (low)
        word(base + 0x024, "DSKLEN");    // Disk length
        word(base + 0x026, "DSKDAT");    // Disk DMA data write
        word(base + 0x028, "REFPTR");    // Refresh pointer
        word(base + 0x02A, "VPOSW");     // Vertical beam position write
        word(base + 0x02C, "VHPOSW");    // Vertical/horizontal beam write
        word(base + 0x02E, "COPCON");    // Copper control
        word(base + 0x030, "SERDAT");    // Serial data and stop bits write
        word(base + 0x032, "SERPER");    // Serial baud rate and mode
        word(base + 0x034, "POTGO");     // Pot port data write/start
        word(base + 0x036, "JOYTEST");   // Write to clear pot/joy
        // Blitter
        word(base + 0x040, "BLTCON0");   // Blitter control 0
        word(base + 0x042, "BLTCON1");   // Blitter control 1
        word(base + 0x044, "BLTAFWM");   // Blitter first word mask (A)
        word(base + 0x046, "BLTALWM");   // Blitter last word mask (A)
        word(base + 0x048, "BLTCPTH");   // Blitter C pointer (high)
        word(base + 0x04A, "BLTCPTL");   // Blitter C pointer (low)
        word(base + 0x04C, "BLTBPTH");   // Blitter B pointer (high)
        word(base + 0x04E, "BLTBPTL");   // Blitter B pointer (low)
        word(base + 0x050, "BLTAPTH");   // Blitter A pointer (high)
        word(base + 0x052, "BLTAPTL");   // Blitter A pointer (low)
        word(base + 0x054, "BLTDPTH");   // Blitter D pointer (high)
        word(base + 0x056, "BLTDPTL");   // Blitter D pointer (low)
        word(base + 0x058, "BLTSIZE");   // Blitter start and size
        word(base + 0x060, "BLTCMOD");   // Blitter C modulo
        word(base + 0x062, "BLTBMOD");   // Blitter B modulo
        word(base + 0x064, "BLTAMOD");   // Blitter A modulo
        word(base + 0x066, "BLTDMOD");   // Blitter D modulo
        word(base + 0x070, "BLTCDAT");   // Blitter C data register
        word(base + 0x072, "BLTBDAT");   // Blitter B data register
        word(base + 0x074, "BLTADAT");   // Blitter A data register
        word(base + 0x07E, "DSKSYNC");   // Disk sync word
        // Copper
        word(base + 0x080, "COP1LCH");   // Copper 1 location (high)
        word(base + 0x082, "COP1LCL");   // Copper 1 location (low)
        word(base + 0x084, "COP2LCH");   // Copper 2 location (high)
        word(base + 0x086, "COP2LCL");   // Copper 2 location (low)
        word(base + 0x088, "COPJMP1");   // Copper restart at copper1
        word(base + 0x08A, "COPJMP2");   // Copper restart at copper2
        word(base + 0x08C, "COPINS");    // Copper instruction fetch
        word(base + 0x08E, "DIWSTRT");   // Display window start
        word(base + 0x090, "DIWSTOP");   // Display window stop
        word(base + 0x092, "DDFSTRT");   // Display bit-plane data fetch start
        word(base + 0x094, "DDFSTOP");   // Display bit-plane data fetch stop
        word(base + 0x096, "DMACON");    // DMA control write (enable/disable)
        word(base + 0x098, "CLXCON");    // Collision control
        word(base + 0x09A, "INTENA");    // Interrupt enable bits write
        word(base + 0x09C, "INTREQ");    // Interrupt request bits write
        word(base + 0x09E, "ADKCON");    // Audio/disk/UART control write
        // Audio channels
        word(base + 0x0A0, "AUD0LCH");   // Audio channel 0 location (high)
        word(base + 0x0A2, "AUD0LCL");   // Audio channel 0 location (low)
        word(base + 0x0A4, "AUD0LEN");   // Audio channel 0 length
        word(base + 0x0A6, "AUD0PER");   // Audio channel 0 period
        word(base + 0x0A8, "AUD0VOL");   // Audio channel 0 volume
        word(base + 0x0AA, "AUD0DAT");   // Audio channel 0 data
        word(base + 0x0B0, "AUD1LCH");   // Audio channel 1 location (high)
        word(base + 0x0B2, "AUD1LCL");   // Audio channel 1 location (low)
        word(base + 0x0B4, "AUD1LEN");   // Audio channel 1 length
        word(base + 0x0B6, "AUD1PER");   // Audio channel 1 period
        word(base + 0x0B8, "AUD1VOL");   // Audio channel 1 volume
        word(base + 0x0BA, "AUD1DAT");   // Audio channel 1 data
        word(base + 0x0C0, "AUD2LCH");   // Audio channel 2 location (high)
        word(base + 0x0C2, "AUD2LCL");   // Audio channel 2 location (low)
        word(base + 0x0C4, "AUD2LEN");   // Audio channel 2 length
        word(base + 0x0C6, "AUD2PER");   // Audio channel 2 period
        word(base + 0x0C8, "AUD2VOL");   // Audio channel 2 volume
        word(base + 0x0CA, "AUD2DAT");   // Audio channel 2 data
        word(base + 0x0D0, "AUD3LCH");   // Audio channel 3 location (high)
        word(base + 0x0D2, "AUD3LCL");   // Audio channel 3 location (low)
        word(base + 0x0D4, "AUD3LEN");   // Audio channel 3 length
        word(base + 0x0D6, "AUD3PER");   // Audio channel 3 period
        word(base + 0x0D8, "AUD3VOL");   // Audio channel 3 volume
        word(base + 0x0DA, "AUD3DAT");   // Audio channel 3 data
        // Bitplane pointers
        word(base + 0x0E0, "BPL1PTH");  word(base + 0x0E2, "BPL1PTL");
        word(base + 0x0E4, "BPL2PTH");  word(base + 0x0E6, "BPL2PTL");
        word(base + 0x0E8, "BPL3PTH");  word(base + 0x0EA, "BPL3PTL");
        word(base + 0x0EC, "BPL4PTH");  word(base + 0x0EE, "BPL4PTL");
        word(base + 0x0F0, "BPL5PTH");  word(base + 0x0F2, "BPL5PTL");
        word(base + 0x0F4, "BPL6PTH");  word(base + 0x0F6, "BPL6PTL");
        // Bitplane control
        word(base + 0x100, "BPLCON0");   // Bitplane control 0
        word(base + 0x102, "BPLCON1");   // Bitplane control 1 (scroll)
        word(base + 0x104, "BPLCON2");   // Bitplane control 2 (priority)
        word(base + 0x108, "BPL1MOD");   // Bitplane 1 modulo (odd planes)
        word(base + 0x10A, "BPL2MOD");   // Bitplane 2 modulo (even planes)
        // Bitplane data registers
        word(base + 0x110, "BPL1DAT");  word(base + 0x112, "BPL2DAT");
        word(base + 0x114, "BPL3DAT");  word(base + 0x116, "BPL4DAT");
        word(base + 0x118, "BPL5DAT");  word(base + 0x11A, "BPL6DAT");
        // Sprite pointers
        word(base + 0x120, "SPR0PTH");  word(base + 0x122, "SPR0PTL");
        word(base + 0x124, "SPR1PTH");  word(base + 0x126, "SPR1PTL");
        word(base + 0x128, "SPR2PTH");  word(base + 0x12A, "SPR2PTL");
        word(base + 0x12C, "SPR3PTH");  word(base + 0x12E, "SPR3PTL");
        word(base + 0x130, "SPR4PTH");  word(base + 0x132, "SPR4PTL");
        word(base + 0x134, "SPR5PTH");  word(base + 0x136, "SPR5PTL");
        word(base + 0x138, "SPR6PTH");  word(base + 0x13A, "SPR6PTL");
        word(base + 0x13C, "SPR7PTH");  word(base + 0x13E, "SPR7PTL");
        // Sprite data
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
        // Color registers
        for (int i = 0; i < 32; i++) {
            word(base + 0x180 + i * 2, String.format("COLOR%02d", i));
        }
    }

    private void mapCIAA() throws Exception {
        // CIA-A at $BFE001 — byte registers on ODD addresses, 256 bytes apart
        long base = 0xBFE000L;
        abyte(base + 0x001, "CIAA_PRA");    // Port A: joy buttons, floppy flags
        abyte(base + 0x101, "CIAA_PRB");    // Port B: parallel port data
        abyte(base + 0x201, "CIAA_DDRA");   // Data direction register A
        abyte(base + 0x301, "CIAA_DDRB");   // Data direction register B
        abyte(base + 0x401, "CIAA_TALO");   // Timer A low byte
        abyte(base + 0x501, "CIAA_TAHI");   // Timer A high byte
        abyte(base + 0x601, "CIAA_TBLO");   // Timer B low byte
        abyte(base + 0x701, "CIAA_TBHI");   // Timer B high byte
        abyte(base + 0x801, "CIAA_TODLO");  // TOD counter low (1/60 s)
        abyte(base + 0x901, "CIAA_TODMID"); // TOD counter mid
        abyte(base + 0xA01, "CIAA_TODHI");  // TOD counter high
        abyte(base + 0xB01, "CIAA_SDR");    // Serial data register
        abyte(base + 0xC01, "CIAA_ICR");    // Interrupt control register
        abyte(base + 0xD01, "CIAA_CRA");    // Control register A
        abyte(base + 0xE01, "CIAA_CRB");    // Control register B
    }

    private void mapCIAB() throws Exception {
        // CIA-B at $BFD000 — byte registers on EVEN addresses, 256 bytes apart
        long base = 0xBFD000L;
        abyte(base + 0x000, "CIAB_PRA");    // Port A: floppy motor/select
        abyte(base + 0x100, "CIAB_PRB");    // Port B: floppy track/status
        abyte(base + 0x200, "CIAB_DDRA");   // Data direction register A
        abyte(base + 0x300, "CIAB_DDRB");   // Data direction register B
        abyte(base + 0x400, "CIAB_TALO");   // Timer A low byte
        abyte(base + 0x500, "CIAB_TAHI");   // Timer A high byte
        abyte(base + 0x600, "CIAB_TBLO");   // Timer B low byte
        abyte(base + 0x700, "CIAB_TBHI");   // Timer B high byte
        abyte(base + 0x800, "CIAB_TODLO");  // Disk position counter low
        abyte(base + 0x900, "CIAB_TODMID"); // Disk position counter mid
        abyte(base + 0xA00, "CIAB_TODHI");  // Disk position counter high
        abyte(base + 0xB00, "CIAB_SDR");    // Serial data register
        abyte(base + 0xC00, "CIAB_ICR");    // Interrupt control register
        abyte(base + 0xD00, "CIAB_CRA");    // Control register A
        abyte(base + 0xE00, "CIAB_CRB");    // Control register B
    }

    private void ensureBlock(String name, long baseAddr, long size) throws Exception {
        Memory mem = currentProgram.getMemory();
        if (mem.getBlock(name) != null) {
            println(name + " block already exists — skipping creation.");
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
        try {
            createWord(a);
        } catch (Exception e) { /* data may already exist */ }
        try {
            currentProgram.getSymbolTable().createLabel(a, name, SourceType.USER_DEFINED);
            labeled++;
        } catch (Exception e) { /* label may already exist */ }
    }

    private void abyte(long addr, String name) throws Exception {
        Address a = toAddr(addr);
        try {
            createByte(a);
        } catch (Exception e) { /* data may already exist */ }
        try {
            currentProgram.getSymbolTable().createLabel(a, name, SourceType.USER_DEFINED);
            labeled++;
        } catch (Exception e) { /* label may already exist */ }
    }
}
