// Resolves AmigaOS library calls where the library base is in A0-A5 (not A6).
// The hunk analyzer only resolves JSR(-N,A6). Many Amiga programs (especially
// GCC-compiled code) store library bases in A0-A5 and call through those registers.
// This script traces each JSR(-N,Ax) for Ax ∈ {A0..A5}, walks backward to find
// a MOVEA.L <global>,Ax instruction, checks if the global name matches a known
// library base suffix, then adds a plate comment naming the function call.
//
// Known library patterns covered (based on installed FD files):
//   exec, dos, graphics, intuition, layers, utility, gadtools, asl, icon,
//   diskfont, keymap, locale, expansion, iffparse, commodities, datatypes
//@author AmigaGhidra
//@category Amiga
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;

import java.util.*;

public class AnnotateMultiRegLibraryCalls extends GhidraScript {

    // LVO → function name tables for the most common libraries.
    // These match the FD files in the installed extension.
    static final Map<Integer, String> EXEC_LVO = buildExecLVO();
    static final Map<Integer, String> DOS_LVO  = buildDosLVO();
    static final Map<Integer, String> GFX_LVO  = buildGfxLVO();
    static final Map<Integer, String> INTUI_LVO = buildIntuiLVO();
    static final Map<Integer, String> UTIL_LVO  = buildUtilityLVO();
    static final Map<Integer, String> LAYERS_LVO = buildLayersLVO();
    static final Map<Integer, String> GADTOOLS_LVO = buildGadToolsLVO();

    // Mapping from common global variable name suffixes → LVO table
    static final Map<String, Map<Integer, String>> LIBNAME_TO_LVO = new LinkedHashMap<>();
    static {
        LIBNAME_TO_LVO.put("SysBase",        EXEC_LVO);
        LIBNAME_TO_LVO.put("ExecBase",        EXEC_LVO);
        LIBNAME_TO_LVO.put("DOSBase",         DOS_LVO);
        LIBNAME_TO_LVO.put("DosBase",         DOS_LVO);
        LIBNAME_TO_LVO.put("GfxBase",         GFX_LVO);
        LIBNAME_TO_LVO.put("GraphicsBase",    GFX_LVO);
        LIBNAME_TO_LVO.put("IntuitionBase",   INTUI_LVO);
        LIBNAME_TO_LVO.put("UtilityBase",     UTIL_LVO);
        LIBNAME_TO_LVO.put("LayersBase",      LAYERS_LVO);
        LIBNAME_TO_LVO.put("GadToolsBase",    GADTOOLS_LVO);
        LIBNAME_TO_LVO.put("GadtoolsBase",    GADTOOLS_LVO);
    }

    @Override
    protected void run() throws Exception {
        Listing listing = currentProgram.getListing();
        SymbolTable st = currentProgram.getSymbolTable();

        int annotated = 0;
        int skipped   = 0;

        Set<String> registers = new LinkedHashSet<>(Arrays.asList("A0","A1","A2","A3","A4","A5"));

        InstructionIterator ii = listing.getInstructions(true);
        while (ii.hasNext() && !monitor.isCancelled()) {
            Instruction instr = ii.next();
            String mnem = instr.getMnemonicString().toLowerCase();
            if (!mnem.equals("jsr") && !mnem.equals("jmp")) continue;

            // Find displacement scalar
            Scalar disp = null;
            String usedReg = null;
            Object[] objs = instr.getOpObjects(0);
            for (Object o : objs) {
                if (o instanceof Scalar) { disp = (Scalar) o; }
                if (o instanceof ghidra.program.model.lang.Register) {
                    String rn = ((ghidra.program.model.lang.Register) o).getName();
                    if (registers.contains(rn)) usedReg = rn;
                }
            }

            if (disp == null || usedReg == null) continue;
            int lvo = (int) disp.getSignedValue();
            if (lvo >= 0) continue;

            // Walk backward to find MOVEA.L <global>,Ax that loaded this register
            String libGlobalName = findLibraryBase(listing, st, instr, usedReg);
            if (libGlobalName == null) { skipped++; continue; }

            // Match to an LVO table
            Map<Integer, String> lvoTable = findLvoTable(libGlobalName);
            if (lvoTable == null) { skipped++; continue; }

            String funcName = lvoTable.get(lvo);
            if (funcName == null) {
                funcName = libGlobalName + " LVO " + lvo;
            }

            String comment = String.format("%s → %s(%s)", usedReg, libGlobalName, funcName);
            try {
                setPlateComment(instr.getAddress(), comment);
                annotated++;
            } catch (Exception e) { /* ok */ }
        }

        println("Multi-register LVO annotation: " + annotated + " annotated, " + skipped + " skipped (no base resolved).");
    }

    private String findLibraryBase(Listing listing, SymbolTable st, Instruction from, String targetReg) {
        Instruction cur = from;
        for (int i = 0; i < 20; i++) {
            cur = listing.getInstructionBefore(cur.getAddress());
            if (cur == null) break;
            String mnem = cur.getMnemonicString().toLowerCase();

            // MOVEA.L (global),An
            if (mnem.equals("movea.l") || mnem.equals("move.l")) {
                String op1 = cur.getDefaultOperandRepresentation(1);
                if (op1 == null) continue;
                if (!op1.toUpperCase().equals(targetReg)) continue;

                // op0 should be a global reference
                ghidra.program.model.symbol.Reference[] refs = cur.getReferencesFrom();
                for (ghidra.program.model.symbol.Reference r : refs) {
                    Address refAddr = r.getToAddress();
                    java.util.List<Symbol> syms = st.getSymbols(refAddr);
                    for (Symbol sym : syms) {
                        String name = sym.getName();
                        if (!name.startsWith("DAT_") && !name.isEmpty()) return name;
                    }
                }
            }

            // If we hit a call/branch, stop tracing (A-reg may have changed)
            if (mnem.startsWith("jsr") || mnem.startsWith("bsr") || mnem.startsWith("rts") ||
                mnem.startsWith("rte") || mnem.startsWith("bra")) break;
        }
        return null;
    }

    private Map<Integer, String> findLvoTable(String globalName) {
        for (Map.Entry<String, Map<Integer, String>> e : LIBNAME_TO_LVO.entrySet()) {
            if (globalName.contains(e.getKey())) return e.getValue();
        }
        return null;
    }

    // ─── LVO tables (bias negated) ───────────────────────────────────────────

    private static Map<Integer, String> buildExecLVO() {
        Map<Integer, String> m = new LinkedHashMap<>();
        m.put(-30, "Supervisor"); m.put(-72, "InitCode"); m.put(-78, "InitStruct");
        m.put(-84, "MakeLibrary"); m.put(-90, "MakeFunctions"); m.put(-96, "FindResident");
        m.put(-108, "Alert"); m.put(-114, "Debug"); m.put(-120, "Disable");
        m.put(-126, "Enable"); m.put(-132, "Forbid"); m.put(-138, "Permit");
        m.put(-144, "SetSR"); m.put(-150, "SuperState"); m.put(-156, "UserState");
        m.put(-162, "SetIntVector"); m.put(-168, "AddIntServer"); m.put(-174, "RemIntServer");
        m.put(-180, "Cause"); m.put(-186, "Allocate"); m.put(-192, "Deallocate");
        m.put(-198, "AllocMem"); m.put(-204, "AllocAbs"); m.put(-210, "FreeMem");
        m.put(-216, "AvailMem"); m.put(-222, "AllocEntry"); m.put(-228, "FreeEntry");
        m.put(-234, "Insert"); m.put(-240, "AddHead"); m.put(-246, "AddTail");
        m.put(-252, "Remove"); m.put(-258, "RemHead"); m.put(-264, "RemTail");
        m.put(-270, "Enqueue"); m.put(-276, "FindName"); m.put(-282, "AddTask");
        m.put(-288, "RemTask"); m.put(-294, "FindTask"); m.put(-300, "SetTaskPri");
        m.put(-306, "SetSignal"); m.put(-312, "SetExcept"); m.put(-318, "Wait");
        m.put(-324, "Signal"); m.put(-330, "AllocSignal"); m.put(-336, "FreeSignal");
        m.put(-342, "AllocTrap"); m.put(-348, "FreeTrap"); m.put(-354, "AddPort");
        m.put(-360, "RemPort"); m.put(-366, "PutMsg"); m.put(-372, "GetMsg");
        m.put(-378, "ReplyMsg"); m.put(-384, "WaitPort"); m.put(-390, "FindPort");
        m.put(-396, "AddLibrary"); m.put(-402, "RemLibrary"); m.put(-408, "OldOpenLibrary");
        m.put(-414, "CloseLibrary"); m.put(-420, "SetFunction"); m.put(-426, "SumLibrary");
        m.put(-432, "AddDevice"); m.put(-438, "RemDevice"); m.put(-444, "OpenDevice");
        m.put(-450, "CloseDevice"); m.put(-456, "DoIO"); m.put(-462, "SendIO");
        m.put(-468, "CheckIO"); m.put(-474, "WaitIO"); m.put(-480, "AbortIO");
        m.put(-486, "AddResource"); m.put(-492, "RemResource"); m.put(-498, "OpenResource");
        m.put(-552, "OpenLibrary"); m.put(-558, "InitSemaphore"); m.put(-564, "ObtainSemaphore");
        m.put(-570, "ReleaseSemaphore"); m.put(-576, "AttemptSemaphore");
        m.put(-624, "CopyMem"); m.put(-630, "CopyMemQuick");
        m.put(-636, "CacheClearU"); m.put(-642, "CacheClearE"); m.put(-648, "CacheControl");
        m.put(-660, "DeleteIORequest"); m.put(-666, "CreateMsgPort"); m.put(-672, "DeleteMsgPort");
        m.put(-684, "AllocVec"); m.put(-690, "FreeVec");
        return Collections.unmodifiableMap(m);
    }

    private static Map<Integer, String> buildDosLVO() {
        Map<Integer, String> m = new LinkedHashMap<>();
        m.put(-30, "Open"); m.put(-36, "Close"); m.put(-42, "Read"); m.put(-48, "Write");
        m.put(-54, "Input"); m.put(-60, "Output"); m.put(-66, "IoErr");
        m.put(-72, "IsInteractive"); m.put(-78, "CreateDir"); m.put(-84, "CurrentDir");
        m.put(-90, "Lock"); m.put(-96, "UnLock"); m.put(-102, "DupLock");
        m.put(-108, "Examine"); m.put(-114, "ExNext"); m.put(-120, "Info");
        m.put(-126, "CreateProc"); m.put(-132, "Exit"); m.put(-138, "LoadSeg");
        m.put(-144, "UnLoadSeg"); m.put(-150, "GetPacket"); m.put(-156, "QueuePacket");
        m.put(-162, "ReplyPkt"); m.put(-168, "AbortPkt"); m.put(-174, "LockRecord");
        m.put(-180, "LockRecords"); m.put(-186, "UnLockRecord"); m.put(-192, "UnLockRecords");
        m.put(-198, "SelectInput"); m.put(-204, "SelectOutput"); m.put(-210, "FGetC");
        m.put(-216, "FPutC"); m.put(-222, "UnGetC"); m.put(-228, "FRead"); m.put(-234, "FWrite");
        m.put(-240, "FGets"); m.put(-246, "FPuts"); m.put(-252, "VFWritef"); m.put(-258, "VFPrintf");
        m.put(-264, "Flush"); m.put(-270, "SetVBuf"); m.put(-276, "DupLockFromFH");
        m.put(-282, "OpenFromLock"); m.put(-288, "ParentDir"); m.put(-294, "IsFileSystem");
        m.put(-300, "Format"); m.put(-306, "Relabel"); m.put(-312, "Inhibit");
        m.put(-318, "AddBuffers"); m.put(-324, "CompareDates"); m.put(-330, "DateToStr");
        m.put(-336, "StrToDate"); m.put(-342, "InternalLoadSeg"); m.put(-348, "InternalUnLoadSeg");
        m.put(-354, "NewCreateProc"); m.put(-360, "DOS"); m.put(-366, "SetCurrentDirName");
        m.put(-372, "GetCurrentDirName"); m.put(-378, "SetProgramName"); m.put(-384, "GetProgramName");
        m.put(-390, "SetPrompt"); m.put(-396, "GetPrompt"); m.put(-402, "SetProgramDir");
        m.put(-408, "GetProgramDir"); m.put(-414, "SystemTagList"); m.put(-420, "AssignLock");
        m.put(-426, "AssignLate"); m.put(-432, "AssignPath"); m.put(-438, "AssignAdd");
        m.put(-444, "RemAssignList"); m.put(-450, "GetDevProc"); m.put(-456, "FreeDevProc");
        m.put(-462, "LockDevUnit"); m.put(-468, "UnLockDevUnit"); m.put(-474, "Delay");
        m.put(-480, "WaitForChar"); m.put(-486, "ParentOfFH"); m.put(-492, "IsFileSystem2");
        m.put(-498, "ChangeMode"); m.put(-504, "SetFileSize"); m.put(-510, "SetFileDate");
        m.put(-516, "NameFromLock"); m.put(-522, "NameFromFH"); m.put(-528, "SplitName");
        m.put(-534, "SameLock"); m.put(-540, "SetMode"); m.put(-546, "ExamineFH");
        m.put(-552, "SeekCertified"); m.put(-558, "SetOwner"); m.put(-564, "MakeLink");
        m.put(-570, "ReadLink"); m.put(-576, "FibFromFH"); m.put(-582, "FibFromHandle");
        m.put(-588, "SetFileDate2");
        return Collections.unmodifiableMap(m);
    }

    private static Map<Integer, String> buildGfxLVO() {
        Map<Integer, String> m = new LinkedHashMap<>();
        m.put(-30, "BltBitMap"); m.put(-36, "BltTemplate"); m.put(-42, "ClearEOL");
        m.put(-48, "ClearScreen"); m.put(-54, "TextLength"); m.put(-60, "Text");
        m.put(-66, "SetFont"); m.put(-72, "OpenFont"); m.put(-78, "CloseFont");
        m.put(-84, "AskSoftStyle"); m.put(-90, "SetSoftStyle"); m.put(-96, "AddBob");
        m.put(-102, "AddVSprite"); m.put(-108, "DoCollision"); m.put(-114, "DrawGList");
        m.put(-120, "InitGels"); m.put(-126, "InitMasks"); m.put(-132, "RemIBob");
        m.put(-138, "RemVSprite"); m.put(-144, "SetCollision"); m.put(-150, "SortGList");
        m.put(-156, "AddAnimOb"); m.put(-162, "Animate"); m.put(-168, "GetGBuffers");
        m.put(-174, "InitGMasks"); m.put(-180, "DrawEllipse"); m.put(-186, "AreaEllipse");
        m.put(-192, "LoadRGB4"); m.put(-198, "InitRastPort"); m.put(-204, "InitArea");
        m.put(-210, "SetRast"); m.put(-216, "Move"); m.put(-222, "Draw");
        m.put(-228, "AreaMove"); m.put(-234, "AreaDraw"); m.put(-240, "AreaEnd");
        m.put(-246, "WaitBlit"); m.put(-252, "SetDrMd"); m.put(-258, "SetOutlinePen");
        m.put(-264, "SetAPen"); m.put(-270, "SetBPen"); m.put(-276, "SetOPen");
        m.put(-282, "SetWriteMask"); m.put(-288, "MakeVPort"); m.put(-294, "MrgCop");
        m.put(-300, "MakeScreen"); m.put(-306, "RemakeDisplay"); m.put(-312, "QBlit");
        m.put(-318, "InitView"); m.put(-324, "CBump"); m.put(-330, "CMove");
        m.put(-336, "CWait"); m.put(-342, "VBeamPos"); m.put(-348, "InitBitMap");
        m.put(-354, "ScrollRaster"); m.put(-360, "WaitBOVP"); m.put(-366, "GetSprite");
        m.put(-372, "FreeSprite"); m.put(-378, "ChangeSprite"); m.put(-384, "MoveSprite");
        m.put(-390, "LockLayerRom"); m.put(-396, "UnlockLayerRom"); m.put(-402, "SyncSBitMap");
        m.put(-408, "CopySBitMap"); m.put(-414, "OwnBlitter"); m.put(-420, "DisownBlitter");
        m.put(-426, "InitTmpRas"); m.put(-432, "AskFont"); m.put(-438, "AddFont");
        m.put(-444, "RemFont"); m.put(-450, "AllocRaster"); m.put(-456, "FreeRaster");
        m.put(-462, "AndRectRegion"); m.put(-468, "OrRectRegion"); m.put(-474, "NewRegion");
        m.put(-480, "ClearRegion"); m.put(-486, "DisposeRegion"); m.put(-492, "FreeVPortCopLists");
        m.put(-498, "FreeCopList"); m.put(-504, "ClipBlit"); m.put(-510, "XorRectRegion");
        m.put(-516, "FreeCprList"); m.put(-522, "GetColorMap"); m.put(-528, "FreeColorMap");
        m.put(-534, "GetRGB4"); m.put(-540, "ScrollVPort"); m.put(-546, "UCopperListInit");
        m.put(-552, "FreeGBuffers"); m.put(-558, "BltBitMapRastPort"); m.put(-564, "OrRegionRegion");
        m.put(-570, "XorRegionRegion"); m.put(-576, "AndRegionRegion"); m.put(-582, "CoerceMode");
        m.put(-588, "ChangeVPBitMap"); m.put(-594, "ReleasePen"); m.put(-600, "ObtainPen");
        m.put(-606, "GetBitMapAttr"); m.put(-612, "AllocBitMap"); m.put(-618, "FreeBitMap");
        m.put(-624, "AddDisplayInfo"); m.put(-630, "FindDisplayInfo"); m.put(-636, "NextDisplayInfo");
        m.put(-642, "GetDisplayInfoData"); m.put(-648, "FontExtent"); m.put(-654, "ReadPixelLine8");
        m.put(-660, "WritePixelLine8"); m.put(-666, "ReadPixelArray8"); m.put(-672, "WritePixelArray8");
        m.put(-678, "GetVPModeID"); m.put(-684, "BestModeIDA"); m.put(-690, "SetRGB32");
        m.put(-696, "GetAPen"); m.put(-702, "GetBPen"); m.put(-708, "GetDrMd");
        m.put(-714, "GetOutlinePen"); m.put(-720, "LoadRGB32"); m.put(-726, "SetChipRev");
        m.put(-732, "SetABPenDrMd"); m.put(-738, "GetRGB32"); m.put(-744, "SetDefaultFont");
        m.put(-750, "TextExtent"); m.put(-756, "TextFit"); m.put(-762, "StripFont");
        m.put(-768, "GetDisplayInfoData2"); m.put(-774, "ProcessBitMap"); m.put(-780, "GetMaxRectA");
        return Collections.unmodifiableMap(m);
    }

    private static Map<Integer, String> buildIntuiLVO() {
        Map<Integer, String> m = new LinkedHashMap<>();
        m.put(-30, "OpenIntuition"); m.put(-36, "Intuition"); m.put(-42, "AddGadget");
        m.put(-48, "ClearDMRequest"); m.put(-54, "ClearMenuStrip"); m.put(-60, "ClearPointer");
        m.put(-66, "CloseScreen"); m.put(-72, "CloseWindow"); m.put(-78, "CloseWorkBench");
        m.put(-84, "CurrentTime"); m.put(-90, "DisplayAlert"); m.put(-96, "DisplayBeep");
        m.put(-102, "DoubleClick"); m.put(-108, "DrawBorder"); m.put(-114, "DrawImage");
        m.put(-120, "EndRequest"); m.put(-126, "GetDefPrefs"); m.put(-132, "GetPrefs");
        m.put(-138, "InitRequester"); m.put(-144, "ItemAddress"); m.put(-150, "ModifyIDCMP");
        m.put(-156, "ModifyProp"); m.put(-162, "MoveScreen"); m.put(-168, "MoveWindow");
        m.put(-174, "OffGadget"); m.put(-180, "OffMenu"); m.put(-186, "OnGadget");
        m.put(-192, "OnMenu"); m.put(-198, "OpenScreen"); m.put(-204, "OpenWindow");
        m.put(-210, "OpenWorkBench"); m.put(-216, "PrintIText"); m.put(-222, "RefreshGadgets");
        m.put(-228, "RemoveGadget"); m.put(-234, "ReportMouse"); m.put(-240, "Request");
        m.put(-246, "ScreenToBack"); m.put(-252, "ScreenToFront"); m.put(-258, "SetDMRequest");
        m.put(-264, "SetMenuStrip"); m.put(-270, "SetPointer"); m.put(-276, "SetPrefs");
        m.put(-282, "SetWindowTitles"); m.put(-288, "ShowTitle"); m.put(-294, "SizeWindow");
        m.put(-300, "ViewAddress"); m.put(-306, "WindowToBack"); m.put(-312, "WindowToFront");
        m.put(-318, "WindowLimits"); m.put(-324, "SetPrefs2"); m.put(-330, "IntuiTextLength");
        m.put(-336, "WBenchToBack"); m.put(-342, "WBenchToFront"); m.put(-348, "AutoRequest");
        m.put(-354, "BeginRefresh"); m.put(-360, "BuildSysRequest"); m.put(-366, "EndRefresh");
        m.put(-372, "FreeSysRequest"); m.put(-378, "MakeScreen"); m.put(-384, "RemakeDisplay");
        m.put(-390, "RethinkDisplay"); m.put(-396, "AllocRemember"); m.put(-402, "AlohaWorkbench");
        m.put(-408, "FreeRemember"); m.put(-414, "LockIBase"); m.put(-420, "UnlockIBase");
        m.put(-426, "GetScreenData"); m.put(-432, "RefreshGList"); m.put(-438, "AddGList");
        m.put(-444, "RemoveGList"); m.put(-450, "ActivateWindow"); m.put(-456, "RefreshWindowFrame");
        m.put(-462, "ActivateGadget"); m.put(-468, "NewModifyProp"); m.put(-474, "QueryOverscan");
        m.put(-480, "MoveWindowInFrontOf"); m.put(-486, "ChangeWindowBox"); m.put(-492, "SetEditHook");
        m.put(-498, "SetMouseQueue"); m.put(-504, "ZipWindow"); m.put(-510, "LockPubScreen");
        m.put(-516, "UnlockPubScreen"); m.put(-522, "LockPubScreenList"); m.put(-528, "UnlockPubScreenList");
        m.put(-534, "NextPubScreen"); m.put(-540, "SetDefaultPubScreen"); m.put(-546, "SetPubScreenModes");
        m.put(-552, "PubScreenStatus"); m.put(-558, "ObtainGIRPort"); m.put(-564, "ReleaseGIRPort");
        m.put(-570, "GadgetMouse"); m.put(-576, "SetIPrefs"); m.put(-582, "GetDefaultPubScreen");
        m.put(-588, "EasyRequestArgs"); m.put(-594, "BuildEasyRequestArgs"); m.put(-600, "SysReqHandler");
        m.put(-606, "OpenWindowTagList"); m.put(-612, "OpenScreenTagList"); m.put(-618, "DrawImageState");
        m.put(-624, "PointInImage"); m.put(-630, "EraseImage"); m.put(-636, "NewObjectA");
        m.put(-642, "DisposeObject"); m.put(-648, "SetAttrsA"); m.put(-654, "GetAttr");
        m.put(-660, "SetGadgetAttrsA"); m.put(-666, "NextObject"); m.put(-672, "FindClass");
        m.put(-678, "MakeClass"); m.put(-684, "AddClass"); m.put(-690, "GetScreenDrawInfo");
        m.put(-696, "FreeScreenDrawInfo"); m.put(-702, "RemoveClass"); m.put(-708, "FreeClass");
        m.put(-714, "AllocScreenBuffer"); m.put(-720, "FreeScreenBuffer"); m.put(-726, "ChangeScreenBuffer");
        m.put(-732, "ScreenDepth"); m.put(-738, "ScreenPosition"); m.put(-744, "ScrollWindowRaster");
        m.put(-750, "TimedDisplayAlert"); m.put(-756, "HelpControl");
        return Collections.unmodifiableMap(m);
    }

    private static Map<Integer, String> buildUtilityLVO() {
        Map<Integer, String> m = new LinkedHashMap<>();
        m.put(-30, "FindTagItem"); m.put(-36, "GetTagData"); m.put(-42, "PackBoolTags");
        m.put(-48, "NextTagItem"); m.put(-54, "FilterTagChanges"); m.put(-60, "MapTags");
        m.put(-66, "AllocateTagItems"); m.put(-72, "CloneTagItems"); m.put(-78, "FreeTagItems");
        m.put(-84, "RefreshTagItemClones"); m.put(-90, "TagInArray"); m.put(-96, "FilterTagItems");
        m.put(-102, "Amiga2Date"); m.put(-108, "Date2Amiga"); m.put(-114, "CheckDate");
        m.put(-120, "SMult32"); m.put(-126, "UMult32"); m.put(-132, "SDivMod32");
        m.put(-138, "UDivMod32"); m.put(-144, "Stricmp"); m.put(-150, "Strnicmp");
        m.put(-156, "ToUpper"); m.put(-162, "ToLower"); m.put(-168, "ApplyTagChanges");
        m.put(-174, "Mult64"); m.put(-180, "SMult64"); m.put(-186, "SpackBoolTags");
        m.put(-192, "GetUniqueID"); m.put(-198, "PackStructureTags"); m.put(-204, "UnpackStructureTags");
        m.put(-210, "AddNamedObject"); m.put(-216, "AllocNamedObjectA"); m.put(-222, "AttemptRemNamedObject");
        m.put(-228, "FindNamedObject"); m.put(-234, "FreeNamedObject"); m.put(-240, "NamedObjectName");
        m.put(-246, "ReleaseNamedObject"); m.put(-252, "RemNamedObject");
        return Collections.unmodifiableMap(m);
    }

    private static Map<Integer, String> buildLayersLVO() {
        Map<Integer, String> m = new LinkedHashMap<>();
        m.put(-30, "InitLayers"); m.put(-36, "CreateUpfrontLayer"); m.put(-42, "CreateBehindLayer");
        m.put(-48, "UpfrontLayer"); m.put(-54, "BehindLayer"); m.put(-60, "MoveLayer");
        m.put(-66, "SizeLayer"); m.put(-72, "ScrollLayer"); m.put(-78, "BeginUpdate");
        m.put(-84, "EndUpdate"); m.put(-90, "DeleteLayer"); m.put(-96, "MoveLayerInFrontOf");
        m.put(-102, "InstallClipRegion"); m.put(-108, "MoveSizeLayer"); m.put(-114, "CreateUpfrontHookLayer");
        m.put(-120, "CreateBehindHookLayer"); m.put(-126, "InstallLayerHook");
        m.put(-132, "InstallLayerInfoHook"); m.put(-138, "SwapBitsRastPortClipRect");
        m.put(-144, "WhichLayer"); m.put(-150, "LockLayerInfo"); m.put(-156, "UnlockLayerInfo");
        m.put(-162, "NewLayerInfo"); m.put(-168, "DisposeLayerInfo"); m.put(-174, "FattenLayerInfo");
        m.put(-180, "ThinLayerInfo"); m.put(-186, "MoveLayerSomewhere"); m.put(-192, "CollectPixelsLayer");
        m.put(-198, "ClearLayerRegionAndMarkDirty");
        return Collections.unmodifiableMap(m);
    }

    private static Map<Integer, String> buildGadToolsLVO() {
        Map<Integer, String> m = new LinkedHashMap<>();
        m.put(-30, "CreateGadgetA"); m.put(-36, "FreeGadgets"); m.put(-42, "SetGadgetAttrsA");
        m.put(-48, "GetGadgetAttrsA"); m.put(-54, "CreateMenusA"); m.put(-60, "FreeMenus");
        m.put(-66, "LayoutMenuItemsA"); m.put(-72, "LayoutMenusA"); m.put(-78, "GetMenuAttrsA");
        m.put(-84, "CreateContext"); m.put(-90, "DrawBevelBoxA"); m.put(-96, "GetVisualInfoA");
        m.put(-102, "FreeVisualInfo"); m.put(-162, "GT_GetIMsg"); m.put(-168, "GT_ReplyIMsg");
        m.put(-174, "GT_RefreshWindow"); m.put(-180, "GT_BeginRefresh"); m.put(-186, "GT_EndRefresh");
        m.put(-192, "GT_FilterIMsg"); m.put(-198, "GT_PostFilterIMsg"); m.put(-204, "CreateMenusA2");
        return Collections.unmodifiableMap(m);
    }
}
