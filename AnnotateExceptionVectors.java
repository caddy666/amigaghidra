// Annotates the 68000 exception vector table at $0-$3FF with named labels.
// Creates an HW_VECTORS memory block at $0 if not already present.
// Labels all 64 standard 68k exception vectors (each is a 4-byte longword pointer)
// plus Amiga-specific level 1-7 interrupt names with their hardware sources.
// Indispensable for Kickstart ROM analysis and bare-metal game/demo reversing.
//@author AmigaGhidra
//@category Amiga
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.SourceType;

public class AnnotateExceptionVectors extends GhidraScript {

    @Override
    protected void run() throws Exception {
        // Ensure vector table block exists ($0-$3FF = 1 KB)
        Memory mem = currentProgram.getMemory();
        if (mem.getBlock("HW_VECTORS") == null) {
            // Only create if $0 is not already covered by a loaded segment
            if (!mem.contains(toAddr(0))) {
                mem.createUninitializedBlock("HW_VECTORS", toAddr(0), 0x400, false);
                MemoryBlock blk = mem.getBlock("HW_VECTORS");
                blk.setRead(true); blk.setWrite(false); blk.setExecute(false);
                println("Created HW_VECTORS block at $00000000");
            } else {
                println("$0 is within an existing block — labeling in place.");
            }
        }

        int n = 0;

        // 68k exception vector table — each entry is a 32-bit pointer to a handler.
        // Amiga copies the ROM vector table to RAM at boot so it can be patched.
        // Vector 0: Initial Supervisor Stack Pointer (value, not a handler pointer)
        // Vector 1: Initial Program Counter (entry point)
        n += vec(0x000, "VECPTR_InitSSP",       "Initial supervisor stack pointer value");
        n += vec(0x004, "VECPTR_InitPC",         "Initial program counter (reset entry)");
        // Hardware errors
        n += vec(0x008, "VECPTR_BusError",       "Bus error (access to unmapped/fault address)");
        n += vec(0x00C, "VECPTR_AddrError",      "Address error (odd address for word/long access)");
        // CPU exceptions
        n += vec(0x010, "VECPTR_IllegalInstr",   "Illegal instruction");
        n += vec(0x014, "VECPTR_DivByZero",      "Divide by zero (DIVS/DIVU)");
        n += vec(0x018, "VECPTR_CHK",            "CHK instruction exception");
        n += vec(0x01C, "VECPTR_TRAPV",          "TRAPV instruction (overflow set)");
        n += vec(0x020, "VECPTR_PrivViol",       "Privilege violation (user mode exec of supervisor instr)");
        n += vec(0x024, "VECPTR_Trace",          "Trace exception (single-step debugging)");
        n += vec(0x028, "VECPTR_LineA",          "Line-A emulator (opcode $Axxx — used by MacOS)");
        n += vec(0x02C, "VECPTR_LineF",          "Line-F emulator (opcode $Fxxx — FPU emulation)");
        // Reserved / 68010+
        n += vec(0x030, "VECPTR_HWBrkpt",       "Hardware breakpoint (68020+ / reserved on 68000)");
        n += vec(0x034, "VECPTR_CoprocProtViol","Coprocessor protocol violation (68020+)");
        n += vec(0x038, "VECPTR_FormatError",   "Stack frame format error (68010+ RTE)");
        n += vec(0x03C, "VECPTR_UninitIntr",    "Uninitialised interrupt (spurious via peripheral)");
        // Vectors 0x040-0x05F reserved
        for (int i = 0x040; i < 0x060; i += 4) {
            n += vec(i, String.format("VECPTR_Reserved_%02X", i / 4), "Reserved");
        }
        // Interrupt autovectors — Amiga hardware assignment
        n += vec(0x064, "VECPTR_AutoLevel1",
            "Amiga Level 1: SOFTINT (software-generated, exec TaskReady queue)");
        n += vec(0x068, "VECPTR_AutoLevel2",
            "Amiga Level 2: DSKBLK (disk DMA done), SOFINT (Paula), PORTS (CIA-A ICR)");
        n += vec(0x06C, "VECPTR_AutoLevel3",
            "Amiga Level 3: COPPER (Copper), VERTB (vertical blank), BLIT (blitter done)");
        n += vec(0x070, "VECPTR_AutoLevel4",
            "Amiga Level 4: AUD0-3 (audio DMA), DSKSYN (disk sync)");
        n += vec(0x074, "VECPTR_AutoLevel5",
            "Amiga Level 5: RBF (serial receive full), DSKSYN (disk sync word match)");
        n += vec(0x078, "VECPTR_AutoLevel6",
            "Amiga Level 6: INTEN (CIA-A/CIA-B timer, keyboard, power), EXTER (CIA-B ICR)");
        n += vec(0x07C, "VECPTR_AutoLevel7",
            "Amiga Level 7: NMI (non-maskable; RESET or parity error) — rarely used");
        // TRAP #0-#15 handlers
        for (int i = 0; i < 16; i++) {
            n += vec(0x080 + i * 4, String.format("VECPTR_TRAP%02d", i),
                String.format("TRAP #%d handler", i));
        }
        // 68020+ vectors (0x0C0-0x0FF)
        n += vec(0x0C0, "VECPTR_FPBranchUn",    "FP branch or set on unordered cond (68040+)");
        n += vec(0x0C4, "VECPTR_FPInexact",     "FP inexact result (68040+)");
        n += vec(0x0C8, "VECPTR_FPDivZero",     "FP divide by zero (68040+)");
        n += vec(0x0CC, "VECPTR_FPUnderflow",   "FP underflow (68040+)");
        n += vec(0x0D0, "VECPTR_FPOperrError",  "FP operand error (68040+)");
        n += vec(0x0D4, "VECPTR_FPOverflow",    "FP overflow (68040+)");
        n += vec(0x0D8, "VECPTR_FPNaN",         "FP signaling NaN (68040+)");
        n += vec(0x0E0, "VECPTR_MMUConfig",     "MMU configuration error (68030/040)");
        n += vec(0x0E4, "VECPTR_MMUIllegal",    "MMU illegal operation (68030/040)");
        n += vec(0x0E8, "VECPTR_MMUAccess",     "MMU access level violation (68030/040)");

        // SysBase pointer — stored here by exec at startup
        try {
            Address sysBaseAddr = toAddr(0x4);
            currentProgram.getSymbolTable().createLabel(sysBaseAddr, "SysBase", SourceType.USER_DEFINED);
            setEOLComment(sysBaseAddr, "exec.library base pointer — always valid after exec init");
        } catch (Exception e) { /* may already exist */ }

        println("Exception vectors: labeled " + n + " entries.");
    }

    private int vec(int offset, String name, String comment) throws Exception {
        Address a = toAddr(offset);
        try { createDWord(a); } catch (Exception e) { /* already defined */ }
        try {
            currentProgram.getSymbolTable().createLabel(a, name, SourceType.USER_DEFINED);
            if (comment != null && !comment.isEmpty()) setEOLComment(a, comment);
            return 1;
        } catch (Exception e) { return 0; }
    }
}
