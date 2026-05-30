// Maps Gayle chip registers for A600 and A1200 IDE/PCMCIA interface.
// Gayle provides ATA/IDE hard drive and PCMCIA Type II slot on A600 (Gayle $D0)
// and A1200 (Gayle $D1). A600 registers have even byte-lane offset; A1200 uses odd.
// The CD32 does NOT have Gayle. The A4000 uses a different direct IDE interface.
// Prompts the user to choose A600 or A1200 byte-lane mapping.
//@author AmigaGhidra
//@category Amiga
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.SourceType;

import java.util.Arrays;
import java.util.List;

public class MapGayleRegisters extends GhidraScript {

    private int labeled = 0;

    @Override
    protected void run() throws Exception {
        List<String> choices = Arrays.asList("A1200 (Gayle $D1, odd byte-lane)", "A600 (Gayle $D0, even byte-lane)");
        String choice = askChoice("Gayle IDE Mapping", "Select target machine:", choices, choices.get(0));
        boolean a1200 = choice.startsWith("A1200");

        // Gayle control registers — same on both A600 and A1200
        ensureBlock("HW_GAYLE_CTRL", 0xDA8000L, 0x2000L);
        abyte(0xDA8000L, "GAYLE_ID");           // Chip ID ($D0=A600, $D1=A1200) — shifts on reads
        abyte(0xDA9000L, "GAYLE_INT_STATUS");   // Interrupt status (IDE + PCMCIA flags)
        abyte(0xDA9004L, "GAYLE_INT_ENABLE");   // Interrupt enable mask
        abyte(0xDA9008L, "GAYLE_CONTROL");      // Control (PCMCIA power, wait states)

        // IDE primary channel registers
        ensureBlock("HW_GAYLE_IDE", 0xDA0000L, 0x2000L);
        if (a1200) {
            // A1200: ATA registers on ODD bytes within each 4-byte window
            word(0xDA0000L, "GAYLE_IDE_DATA");       // Data register (16-bit)
            abyte(0xDA0005L, "GAYLE_IDE_ERR_FEAT");  // Error (R) / Features (W)
            abyte(0xDA0009L, "GAYLE_IDE_SECCOUNT");  // Sector count
            abyte(0xDA000DL, "GAYLE_IDE_SECNUM");    // Sector number / LBA[7:0]
            abyte(0xDA0011L, "GAYLE_IDE_CYLLO");     // Cylinder low / LBA[15:8]
            abyte(0xDA0015L, "GAYLE_IDE_CYLHI");     // Cylinder high / LBA[23:16]
            abyte(0xDA0019L, "GAYLE_IDE_DRVHEAD");   // Drive/head / LBA[27:24]
            abyte(0xDA001DL, "GAYLE_IDE_STATUS_CMD");// Status (R) / Command (W)
            abyte(0xDA101DL, "GAYLE_IDE_ALTSTAT");   // Alternate status / device control
            println("IDE registers mapped for A1200 (odd byte-lane).");
        } else {
            // A600: ATA registers on EVEN bytes
            word(0xDA0000L, "GAYLE_IDE_DATA");
            abyte(0xDA0004L, "GAYLE_IDE_ERR_FEAT");
            abyte(0xDA0008L, "GAYLE_IDE_SECCOUNT");
            abyte(0xDA000CL, "GAYLE_IDE_SECNUM");
            abyte(0xDA0010L, "GAYLE_IDE_CYLLO");
            abyte(0xDA0014L, "GAYLE_IDE_CYLHI");
            abyte(0xDA0018L, "GAYLE_IDE_DRVHEAD");
            abyte(0xDA001CL, "GAYLE_IDE_STATUS_CMD");
            abyte(0xDA101CL, "GAYLE_IDE_ALTSTAT");
            println("IDE registers mapped for A600 (even byte-lane).");
        }

        setPlateComment(toAddr(0xDA8000L),
            "GAYLE_ID: Each read shifts the ID byte one bit.\n" +
            "$D0 = A600 Gayle,  $D1 = A1200 Gayle.\n" +
            "On non-Gayle machines this returns bus noise.");

        println("Gayle: labeled " + labeled + " registers total.");
    }

    private void ensureBlock(String name, long baseAddr, long size) throws Exception {
        Memory mem = currentProgram.getMemory();
        if (mem.getBlock(name) != null) { println(name + " already exists."); return; }
        mem.createUninitializedBlock(name, toAddr(baseAddr), size, false);
        MemoryBlock blk = mem.getBlock(name);
        blk.setRead(true); blk.setWrite(true); blk.setExecute(false); blk.setVolatile(true);
        println("Created " + name + " at 0x" + Long.toHexString(baseAddr).toUpperCase());
    }

    private void abyte(long addr, String name) throws Exception {
        Address a = toAddr(addr);
        try { createByte(a); } catch (Exception e) { /* already */ }
        try { currentProgram.getSymbolTable().createLabel(a, name, SourceType.USER_DEFINED); labeled++; }
        catch (Exception e) { /* already */ }
    }

    private void word(long addr, String name) throws Exception {
        Address a = toAddr(addr);
        try { createWord(a); } catch (Exception e) { /* already */ }
        try { currentProgram.getSymbolTable().createLabel(a, name, SourceType.USER_DEFINED); labeled++; }
        catch (Exception e) { /* already */ }
    }
}
