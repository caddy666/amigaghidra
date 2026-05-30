// Maps Amiga Real-Time Clock (RTC) registers to named labels.
// The Amiga uses either an Oki MSM6242B or Ricoh RF5C01A RTC chip at $DC0000.
// Each register is a 4-bit nibble, one per 4-byte slot = 16 registers × 4 bytes = 64 bytes.
// The RTC chip provides BCD-encoded time/date; some models (A500, A2000 without clock
// expansion, CD32) do not have an RTC — reading $DC0000 returns bus noise.
//@author AmigaGhidra
//@category Amiga
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.SourceType;

public class MapRTCRegisters extends GhidraScript {

    @Override
    protected void run() throws Exception {
        long rtcBase = 0xDC0000L;
        long rtcSize = 0x40L; // 64 bytes: 16 registers × 4 bytes each

        Memory mem = currentProgram.getMemory();
        if (mem.getBlock("HW_RTC") == null) {
            mem.createUninitializedBlock("HW_RTC", toAddr(rtcBase), rtcSize, false);
            MemoryBlock blk = mem.getBlock("HW_RTC");
            blk.setRead(true); blk.setWrite(true);
            blk.setExecute(false); blk.setVolatile(true);
            println("Created HW_RTC block at $DC0000");
        } else {
            println("HW_RTC block already exists.");
        }

        // MSM6242B / RF5C01A RTC register layout.
        // Each register uses only the low 4 bits (BCD nibble).
        // Physical address = $DC0000 + (register_number × 4).
        String[][] regs = {
            {"RTC_SEC1",    "Seconds ones digit (BCD 0-9)"},
            {"RTC_SEC10",   "Seconds tens digit (BCD 0-5)"},
            {"RTC_MIN1",    "Minutes ones digit (BCD 0-9)"},
            {"RTC_MIN10",   "Minutes tens digit (BCD 0-5)"},
            {"RTC_HOUR1",   "Hours ones digit (BCD 0-9)"},
            {"RTC_HOUR10",  "Hours tens digit (BCD 0-2) / AM=0/PM=1 bit in 12h mode"},
            {"RTC_WDAY",    "Day of week (1=Monday … 7=Sunday)"},
            {"RTC_DAY1",    "Day ones digit (BCD 1-9)"},
            {"RTC_DAY10",   "Day tens digit (BCD 0-3)"},
            {"RTC_MON1",    "Month ones digit (BCD 1-9)"},
            {"RTC_MON10",   "Month tens digit (BCD 0-1)"},
            {"RTC_YEAR1",   "Year ones digit (BCD 0-9)"},
            {"RTC_YEAR10",  "Year tens digit (BCD 0-9)"},
            {"RTC_CTRL_D",  "Control register D: HOLD, BUSY, IRQ1, IRQ2 bits"},
            {"RTC_CTRL_E",  "Control register E: mask/enable bits"},
            {"RTC_CTRL_F",  "Control register F: 12/24h, STOP, RESET, TEST bits"},
        };

        int n = 0;
        for (int i = 0; i < regs.length; i++) {
            long addr = rtcBase + i * 4L;
            Address a = toAddr(addr);
            try { createByte(a); } catch (Exception e) { /* already defined */ }
            try {
                currentProgram.getSymbolTable().createLabel(a, regs[i][0], SourceType.USER_DEFINED);
                setEOLComment(a, regs[i][1]);
                n++;
            } catch (Exception e) { /* already labeled */ }
        }

        setPlateComment(toAddr(rtcBase),
            "Amiga Real-Time Clock (Oki MSM6242B or Ricoh RF5C01A)\n" +
            "Base: $DC0000. Each register = 4 bits, spaced 4 bytes apart.\n" +
            "AmigaOS accesses via battery.resource (battery.device on OS 3.x).\n" +
            "Not present on stock A500/A2000 without clock expansion, nor on CD32.");

        println("RTC: labeled " + n + " registers.");
    }
}
