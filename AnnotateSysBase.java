// Annotates the SysBase pointer at $4 and decodes ExecBase struct field addresses.
// The hunk loader creates the library base and applies the ExecLib data type, but
// this script adds labeled addresses for each field so they are navigable from the
// symbol table, and adds plate/EOL comments explaining each ExecBase member.
// Also labels the global SysBase pointer at address $4.
//
// Addresses without an existing memory block at $4 will have a 4-byte block created.
// If SysBase itself is in memory (e.g., when analyzing a Kickstart ROM or full RAM dump),
// the script decodes and displays key fields directly.
//@author AmigaGhidra
//@category Amiga
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.SourceType;

public class AnnotateSysBase extends GhidraScript {

    @Override
    protected void run() throws Exception {
        Memory mem = currentProgram.getMemory();

        // Ensure $4 is accessible as a memory location
        if (!mem.contains(toAddr(4))) {
            if (!mem.contains(toAddr(0))) {
                mem.createUninitializedBlock("HW_SYSBASE_PTR", toAddr(0x4), 4, false);
            }
        }

        // Label $4 as SysBase pointer
        Address sysBaseAddr = toAddr(0x4);
        try {
            createDWord(sysBaseAddr);
        } catch (Exception e) { /* already defined */ }
        try {
            currentProgram.getSymbolTable().createLabel(sysBaseAddr, "SysBase", SourceType.USER_DEFINED);
        } catch (Exception e) { /* already labeled */ }
        setPlateComment(sysBaseAddr,
            "SysBase — exec.library base pointer\n" +
            "Always valid after exec initialises. This longword holds\n" +
            "the runtime address of struct ExecBase.\n" +
            "Set by Kickstart at boot; used by ALL OS library calls.\n" +
            "Access: MOVEA.L 4.W,A6  (AmigaOS standard idiom)");
        setEOLComment(sysBaseAddr, "exec.library base — struct ExecBase *");

        // Try to locate the actual ExecBase in memory
        // For a running Kickstart ROM or full RAM snapshot, the value at $4 is valid.
        long execBaseAddr = 0;
        boolean liveExecBase = false;
        try {
            if (mem.contains(sysBaseAddr)) {
                execBaseAddr = mem.getInt(sysBaseAddr, false) & 0xFFFFFFFFL;
                liveExecBase = execBaseAddr != 0 && mem.contains(toAddr(execBaseAddr));
            }
        } catch (Exception e) { /* not readable */ }

        if (liveExecBase) {
            println(String.format("Found live ExecBase at 0x%08X — annotating fields.", execBaseAddr));
            annotateExecBase(mem, toAddr(execBaseAddr));
        } else {
            println("SysBase at $4 is not resolvable to a loaded address.");
            println("Annotating ExecBase field schema as reference at the SysBase pointer.");
            annotateExecBaseSchema();
        }

        println("SysBase annotation complete.");
    }

    private void annotateExecBase(Memory mem, Address base) throws Exception {
        // struct Library (embedded in ExecBase at +$0)
        field(base, 0x00, "ExecBase_ln_Succ",    "struct Node: ln_Succ (next in LibList)");
        field(base, 0x04, "ExecBase_ln_Pred",    "struct Node: ln_Pred (prev in LibList)");
        field(base, 0x08, "ExecBase_ln_Type",    "struct Node: ln_Type = NT_LIBRARY (9)");
        field(base, 0x09, "ExecBase_ln_Pri",     "struct Node: ln_Pri = priority");
        field(base, 0x0A, "ExecBase_ln_Name",    "struct Node: ln_Name → \"exec.library\"");
        field(base, 0x0E, "ExecBase_lib_Flags",  "LIBF_SUMUSED|LIBF_CHANGED flags");
        field(base, 0x10, "ExecBase_lib_NegSize","JMP table size in bytes");
        field(base, 0x12, "ExecBase_lib_PosSize","Library struct + private data size");
        field(base, 0x14, "ExecBase_lib_Version","exec major version number");
        field(base, 0x16, "ExecBase_lib_Revision","exec minor revision");
        field(base, 0x18, "ExecBase_lib_IdString","→ \"exec.library N.n (date)\\r\\n\"");
        field(base, 0x1C, "ExecBase_lib_Sum",    "JMP table checksum");
        field(base, 0x20, "ExecBase_lib_OpenCnt","Open count (always 1 for exec)");
        // ExecBase-specific fields
        // ExecBase-specific fields (verified against NDK exec/execbase.h)
        field(base, 0x22, "ExecBase_SoftVer",    "Kickstart software version (UWORD)");
        field(base, 0x24, "ExecBase_LowMemChkSum","Chip RAM checksum low word (WORD)");
        field(base, 0x26, "ExecBase_ChkBase",    "Checksum verification base pointer (ULONG)");
        field(base, 0x2A, "ExecBase_ColdCapture","Cold boot capture vector — NULL normally (APTR)");
        field(base, 0x2E, "ExecBase_CoolCapture","Cool boot capture vector (APTR)");
        field(base, 0x32, "ExecBase_WarmCapture","Warm reboot capture vector (APTR)");
        field(base, 0x36, "ExecBase_SysStkUpper","Top of supervisor stack (APTR)");
        field(base, 0x3A, "ExecBase_SysStkLower","Bottom of supervisor stack (APTR)");
        field(base, 0x3E, "ExecBase_MaxLocMem",  "Top of local Chip RAM (ULONG)");
        field(base, 0x42, "ExecBase_DebugEntry", "Debugger entry point (APTR)");
        field(base, 0x46, "ExecBase_DebugData",  "Debugger private data (APTR)");
        field(base, 0x4A, "ExecBase_AlertData",  "Alert scratch area pointer (APTR)");
        field(base, 0x4E, "ExecBase_MaxExtMem",  "Top of extended Fast RAM (APTR)");
        field(base, 0x52, "ExecBase_ChkSum",     "ExecBase checksum (UWORD)");
        field(base, 0x54, "ExecBase_IntVects",   "16 interrupt vectors: struct IntVector[16] (192 bytes)");
        // After IntVects[16] (12 bytes each = $C0 bytes): starts at $54 + $C0 = $114
        field(base, 0x114,"ExecBase_ThisTask",   "→ currently running Task/Process (APTR)");
        field(base, 0x118,"ExecBase_IdleCount",  "Idle loop counter (ULONG)");
        field(base, 0x11C,"ExecBase_DispCount",  "Dispatch counter (ULONG)");
        field(base, 0x120,"ExecBase_Quantum",    "Task time quantum in ticks (UWORD)");
        field(base, 0x122,"ExecBase_Elapsed",    "Ticks used in current quantum (UWORD)");
        field(base, 0x124,"ExecBase_SysFlags",   "System flags (UWORD)");
        field(base, 0x126,"ExecBase_IDNestCnt",  "Interrupt disable nesting count (BYTE)");
        field(base, 0x127,"ExecBase_TDNestCnt",  "Task disable nesting count (BYTE)");
        field(base, 0x128,"ExecBase_AttnFlags",  "CPU capability flags: AFF_68020=$0002, AFF_FPU=$0010 (UWORD)");
        field(base, 0x12A,"ExecBase_AttnResched","Reschedule attention flag (UWORD)");
        field(base, 0x12C,"ExecBase_ResModules", "→ NULL-terminated Resident module pointer table (APTR)");
        field(base, 0x130,"ExecBase_TaskTrapCode","Default task exception handler (APTR)");
        field(base, 0x134,"ExecBase_TaskExceptCode","Task exception code (APTR)");
        field(base, 0x138,"ExecBase_TaskExitCode","Task exit code (APTR)");
        field(base, 0x13C,"ExecBase_TaskSigAlloc","Allocated signal mask (ULONG)");
        field(base, 0x140,"ExecBase_TaskTrapAlloc","Allocated trap mask (UWORD)");
        field(base, 0x142,"ExecBase_MemList",    "struct List: memory headers (AvailMem source)");
        field(base, 0x14E,"ExecBase_ResourceList","struct List: open resources");
        field(base, 0x15A,"ExecBase_DeviceList", "struct List: open devices");
        field(base, 0x166,"ExecBase_IntrList",   "struct List: software interrupt handlers");
        field(base, 0x172,"ExecBase_LibList",    "struct List: open libraries — traverse for all open libs");
        field(base, 0x17E,"ExecBase_PortList",   "struct List: message ports");
        field(base, 0x18A,"ExecBase_TaskReady",  "struct List: ready-to-run task queue");
        field(base, 0x196,"ExecBase_TaskWait",   "struct List: waiting task queue");
        field(base, 0x1A2,"ExecBase_SoftIntList","struct SoftIntList[5]: soft interrupt levels");

        setPlateComment(base,
            "struct ExecBase (exec.library base)\n" +
            "Pointer stored at $4. Contains all exec global state:\n" +
            "memory lists, library/device lists, task queues, interrupt\n" +
            "vectors, CPU capability flags, and the exec JMP table below.");

        println("ExecBase fields annotated at 0x" + base.toString());

        // Read AttnFlags to report CPU capabilities
        try {
            int attnFlags = mem.getShort(base.add(0xEA)) & 0xFFFF;
            println(String.format("  AttnFlags = 0x%04X (%s)", attnFlags, decodeAttnFlags(attnFlags)));
        } catch (Exception e) { /* ignore */ }
    }

    private void annotateExecBaseSchema() throws Exception {
        // Just print the schema as console info when ExecBase isn't in memory
        println("ExecBase struct field reference (exec/execbase.h):");
        println("  +$00  ln_Succ    — next in LibList");
        println("  +$10  lib_NegSize — JMP table size");
        println("  +$14  lib_Version — exec major version");
        println("  +$22  SoftVer     — Kickstart software version");
        println("  +$EA  AttnFlags   — CPU flags (AFF_68020=$0002, AFF_68040=$0004, AFF_FPU=$0010)");
        println("  +$104 MemList     — memory headers list");
        println("  +$134 LibList     — open library list");
        println("  +$14C TaskReady   — ready task queue");
        println("  +$EE  ResModules  — Resident module pointer table");
    }

    private void field(Address base, int offset, String name, String comment) throws Exception {
        Address a = base.add(offset);
        if (!currentProgram.getMemory().contains(a)) return;
        try {
            currentProgram.getSymbolTable().createLabel(a, name, SourceType.USER_DEFINED);
        } catch (Exception e) { /* already labeled */ }
        if (comment != null) {
            try { setEOLComment(a, comment); } catch (Exception e) { /* ok */ }
        }
    }

    private String decodeAttnFlags(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & 0x0002) != 0) sb.append("68020+ ");
        if ((flags & 0x0004) != 0) sb.append("68030+ ");
        if ((flags & 0x0008) != 0) sb.append("68040+ ");
        if ((flags & 0x0010) != 0) sb.append("FPU ");
        if ((flags & 0x0020) != 0) sb.append("PMMU ");
        if ((flags & 0x0040) != 0) sb.append("68060 ");
        if ((flags & 0x8000) != 0) sb.append("PAL ");
        return sb.length() == 0 ? "68000" : sb.toString().trim();
    }
}
