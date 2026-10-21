#define TESLA_INIT_IMPL
#include <tesla.hpp>

#include "debugger.hpp"
#include "dmntcht.h"
#include "memory_dump.hpp"
#include "utils.hpp"
#include <ctime>

using namespace tsl;

bool dmnt_present = false;

char Variables[672];

struct toggle_list_t {
    u32 keycode;
    u32 cheat_id;
    // Stable identifier: dmnt reassigns cheat_id whenever a cheat is removed
    // and re-added (e.g. after editing key combos, after reload, etc.). Keep
    // the readable_name alongside the cached id so we can resolve the live
    // cheat_id at use time and avoid toggling the wrong entry.
    char name[0x40];
};
std::vector<toggle_list_t> m_toggle_list;
bool refresh_cheats = true;

// Bookmark display
bool m_showALlCheats = false;
std::string Title_str = "";
#define MAX_POINTER_DEPTH 12
struct pointer_chain_t {
    u64 depth = 0;
    s64 offset[MAX_POINTER_DEPTH + 1] = {0};  // offset to address pointed by pointer
};
struct bookmark_t {
    char label[19] = {0};
    searchType_t type;
    pointer_chain_t pointer;
    bool heap = true;
    u64 offset = 0;
    bool deleted = false;
    u8 multiplier = 1;
	u16 magic = 0x1289;
};
typedef struct {
    bool is_outline = false;
    bool always_expanded = false;
    bool expanded = false;
    uint32_t index = 0, size = 0;
    // Group title shown on a collapsed section header row (extracted from a
    // --SectionStart:<title>-- marker; empty for opcode-style markers, which
    // fall back to the cheat's readable_name at render time).
    std::string title;
} cheat_outline_entry_t;
std::vector<cheat_outline_entry_t> m_cheat_outline;
bool m_outline_mode = true;
bool m_outline_refresh = true;
// Authoritative record of which section groups the user has expanded, keyed by
// the begin-marker index into m_cheats[]. Kept separate from m_cheat_outline so
// that toggling a cheat (which refreshes but does not rebuild the outline) or a
// delete-driven rebuild can always reconstruct a group's children consistently:
// a collapsed group (absent from here) never renders its children, even when one
// of them is enabled.
std::vector<u32> m_expanded_groups;
bool show_outline_off = false;
#define NUM_bookmark 10
#define MAX_NUM_cheats 35
u32 m_NUM_cheats = 20;
#define NUM_cheats m_NUM_cheats
#define NUM_combokey 3
u32 total_opcode = 0;
// Flat (non-outline) view: screen row -> raw m_cheats index, rebuilt once per
// getcheats() pass by skipping section markers (and disabled cheats in the
// enabled-only view) with a LOCAL cursor. m_cheatlist_offset is never mutated
// for skipping, or the every-frame pass would drift it past the end and blank
// the list. The renderer, info line and every non-outline action resolve the
// highlighted cheat through this map (see FlatSelectedRaw).
u32 m_flat_row_raw[MAX_NUM_cheats];
u32 m_flat_row_count = 0;
u32 m_real_cheat_count = 0;   // marker-free total, shown by the flat info line
u32 m_last_real_raw = 0;      // raw index of the last selectable cheat in the current view (bounds the cursor)
#define MaxCheatCount 0x80
#define MaxOpcodes 0x100
#define MaximumProgramOpcodeCount 0x400
u8 fontsize = 14;
bool m_editCheat = false;
u8 keycount;
Result rc;
std::string m_titleName = "", m_titleName2 = "", m_versionString = "";
// Upper bound for cheat / toggle text files read into memory. Guards against a
// failed ftell() (-1 wrapping to SIZE_MAX) or a corrupt/huge file making the
// allocation below throw bad_alloc, which would std::terminate the overlay
// (exceptions are enabled but never caught on these parse paths).
static constexpr size_t CHEAT_FILE_MAX_LEN = 4u * 1024u * 1024u; // 4 MiB

char m_cheatcode_path[128];
char m_toggle_path[128];
u64 m_cheatCnt = 0; 
std::unique_ptr<DmntCheatEntry[]> m_cheats;
struct outline_t {
    std::string label;
    u32 index;
};

// Cache
struct cache_outline_t {
    std::string label;
    bool selected = false;
    bool is_outline = false;
    bool expanded = false;
    bool always_expanded = false;
    u32 size = 0;
    u32 index;  // m_cheatlist_offset
};
std::vector<cache_outline_t> m_cache_outline;
std::vector<DmntCheatEntry> m_cache;
// end Cache

u32 m_outline_index = 0;
bool m_show_outline = false;
std::vector<outline_t> m_outline;
bool save_code_to_file = false;
// Set whenever the user flips a cheat's enabled state (A-button checkbox or a
// key-combo toggle). getcheats() flushes the current dmnt state to toggles.brz
// as soon as it has re-read m_cheats, so the persisted enable/disable always
// matches the latest user intent. Without this, toggles.brz is only rewritten
// on the edit-exit path (save_code_to_file), so a plain check-then-uncheck left
// a stale 'true' behind that loadtoggles() would re-apply on the next reload
// from the .txt, resurrecting a cheat the user had just unchecked.
bool save_toggles_to_file = false;
bool m_edit_value = false;
bool m_hex_mode = false;
bool m_get_toggle_keycode = false;
bool m_get_action_keycode = false;
bool save_breeze_toggle_to_file = false;
bool save_breeze_action_to_file = false;
bool first_launch = true;
static const std::vector<std::string> keyNames = {"0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F","-","."};
static const std::vector<std::string> actionNames = {"+","*","Set","Freeze","Unfreeze"};
typedef enum {
    Add,
    Multipy,
    Set,
    Freeze,
    Unfreeze
} breeze_action_t;
struct breeze_action_list_t {
    u32 keycode = 0;
    breeze_action_t breeze_action = Add;
    searchValue_t value = {0}, freeze_value = {0};
    u8 index = 0;
};
std::vector<breeze_action_list_t> m_breeze_action_list;
std::string valueStr = "";
u8 value_pos =0;
u8 m_value_edit_index = 0;
u64 m_selected_address;
searchType_t m_selected_type;
typedef enum {
    Display,
    Insert,
    Delete
} valueStr_action_t;

static const std::vector<u32> buttonCodes = {0x80000001,
                                             0x80000002,
                                             0x80000004,
                                             0x80000008,
                                             0x80000010,
                                             0x80000020,
                                             0x80000040,
                                             0x80000080,
                                             0x80000100,
                                             0x80000200,
                                             0x80000400,
                                             0x80000800,
                                             0x80001000,
                                             0x80002000,
                                             0x80004000,
                                             0x80008000,
                                             0x80010000,
                                             0x80020000,
                                             0x80040000,
                                             0x80080000,
                                             0x80100000,
                                             0x80200000,
                                             0x80400000,
                                             0x80800000};
static const std::vector<std::string> buttonNames = {"\uE0A0 ", "\uE0A1 ", "\uE0A2 ", "\uE0A3 ", "\uE0C4 ", "\uE0C5 ", "\uE0A4 ", "\uE0A5 ", "\uE0A6 ", "\uE0A7 ", "\uE0B3 ", "\uE0B4 ", "\uE0B1 ", "\uE0AF ", "\uE0B2 ", "\uE0B0 ", "\uE091 ", "\uE092 ", "\uE090 ", "\uE093 ", "\uE145 ", "\uE143 ", "\uE146 ", "\uE144 "};

char BookmarkLabels[NUM_bookmark * 20 + MAX_NUM_cheats * 0x41] = "";
char Cursor[NUM_bookmark * 5 + MAX_NUM_cheats * 5 + 1000] = "";
char MultiplierStr[NUM_bookmark * 5 + MAX_NUM_cheats * 0x41 ] = "";
char CheatsLabelsStr[MAX_NUM_cheats * 0x41 ] = "";
char CheatsCursor[MAX_NUM_cheats * 5 +500 ] = "";
char CheatsEnableStr[MAX_NUM_cheats * 0x41] = "";
#define m_err_str CheatsLabelsStr
bool m_show_only_enabled_cheats = true;
bool m_cursor_on_bookmark = true;
bool m_no_cheats = true;
bool m_no_bookmarks = true;
bool m_game_not_running = true;
bool m_on_show = false;
u32 m_displayed_bookmark_lines = 0;
u32 m_displayed_cheat_lines = 0;
u32 m_index = 0;
u32 m_cheat_index = 0, m_cheat_index_save = 0;
std::string m_edizon_dir = "/switch/EdiZon";
std::string m_store_extension = "A";
std::unique_ptr<Debugger> m_debugger;
std::unique_ptr<MemoryDump> m_AttributeDumpBookmark;
u8 m_addresslist_offset = 0;
u32 m_cheatlist_offset = 0, m_cheatlist_offset_save = 0;
bool m_32bitmode = false;
static const std::vector<u8> dataTypeSizes = {1, 1, 2, 2, 4, 4, 8, 8, 4, 8, 8};

// dataTypeSizes covers the 11 concrete types (index 0..SEARCH_TYPE_POINTER).
// bookmark.type / m_selected_type can hold an arbitrary value when read back
// from a corrupt or legacy .dat; raw-indexing with it would read past the
// vector and hand a garbage width to read/writeMemory, which then overruns the
// 8-byte searchValue_t. Return 0 for anything out of range so the access is
// skipped instead of corrupting memory.
static inline size_t DataTypeSize(searchType_t type) {
    return (static_cast<size_t>(type) < dataTypeSizes.size())
               ? dataTypeSizes[static_cast<size_t>(type)]
               : 0;
}
searchValue_t m_oldvalue[NUM_bookmark] = {0};
DmntCheatProcessMetadata metadata;
char bookmarkfilename[200] = "bookmark filename";
u8 build_id[0x20];

std::string valueStr_edit_display(valueStr_action_t action) {
    std::string tempstr = valueStr;
    switch (action) {
        case Display:
            return tempstr.insert(value_pos,"|");
        case Insert:
            return valueStr.insert(value_pos, keyNames[m_value_edit_index]);
        case Delete:
            if ((valueStr.length() > 0) && (value_pos <= valueStr.length()) && (value_pos > 0))
                return valueStr.erase(value_pos - 1, 1);
            return valueStr;
    }
    return "";
}

bool isServiceRunning(const char *serviceName) {
    Handle handle;
    SmServiceName service_name = smEncodeName(serviceName);
    if (R_FAILED(smRegisterService(&handle, service_name, false, 1)))
        return true;
    else {
        svcCloseHandle(handle);
        smUnregisterService(service_name);
        return false;
    }
}

bool init_se_tools() {
    dmnt_present = isServiceRunning("dmnt:cht");
    if (!dmnt_present) return false;

    m_debugger = std::make_unique<Debugger>();
    uint64_t PID = 0;
    int64_t timeout = 1000'000'000;
    int64_t interval = 10'000'000;
    while (timeout) {
        if (R_SUCCEEDED(pmdmntGetApplicationProcessId(&PID))) {
            dmntchtForceOpenCheatProcess();
            break;
        }
        timeout -= interval;
        svcSleepThread(interval);
    }
    dmntchtHasCheatProcess(&(m_debugger->m_dmnt));
    if (m_debugger->m_dmnt) {
        dmntchtGetCheatProcessMetadata(&metadata);
        size_t appControlDataSize = 0;
        static NsApplicationControlData m_appControlData = {};
        NacpLanguageEntry *languageEntry = nullptr;
        std::memset(&m_appControlData, 0x00, sizeof(NsApplicationControlData));
        rc = nsGetApplicationControlData(NsApplicationControlSource_Storage, metadata.title_id & 0xFFFFFFFFFFFFFFF0, &m_appControlData, sizeof(NsApplicationControlData), &appControlDataSize);
        if (rc == 0) {
            rc = nsGetApplicationDesiredLanguage(&m_appControlData.nacp, &languageEntry);
            if (languageEntry != nullptr) {
                m_titleName = std::string(languageEntry->name);
            }
            m_versionString = std::string(m_appControlData.nacp.display_version);
        }
    } else {
        // No live cheat process: leave the overlay in a clean "not attached"
        // state. m_debugger was allocated above but is unusable here, so free
        // it; cleanup_se_tools() also resets it, which is a safe no-op once
        // the unique_ptr is already null.
        m_debugger.reset();
        return false;
    }

    memcpy(build_id, metadata.main_nso_build_id, 0x20);

    snprintf(bookmarkfilename, 200, "%s/%02x%02x%02x%02x%02x%02x%02x%02x.dat", EDIZON_DIR,
             build_id[0], build_id[1], build_id[2], build_id[3], build_id[4], build_id[5], build_id[6], build_id[7]);

    m_AttributeDumpBookmark = std::make_unique<MemoryDump>(bookmarkfilename, DumpType::ADDR, false);

    return true;
}

void cleanup_se_tools() {
    m_debugger.reset();
    m_AttributeDumpBookmark.reset();
}

// Read one pointer-chain step from the cheat process. The old code did
//   readMemory(&nextaddress, m_32bitmode ? 4 : 8, nextaddress)
// which on aarch64 LP64 only overwrites the low 32 bits of the u64
// `nextaddress` and leaves the upper 32 bits holding the *previous* step's
// value, producing a wrong 64-bit pointer. Going through a typed local
// guarantees the high bits are zeroed in 32-bit mode.
static inline u64 ReadPointerStep(Debugger *dbg, u64 addr) {
    if (dbg == nullptr) return 0;
    if (m_32bitmode) {
        u32 v32 = 0;
        dbg->readMemory(&v32, sizeof(v32), addr);
        return (u64)v32;
    }
    u64 v64 = 0;
    dbg->readMemory(&v64, sizeof(v64), addr);
    return v64;
}

// Keep at most MAX_BACKUPS rolling copies of the cheat .txt before it is
// truncated and rewritten by dumpcodetofile(). Named <path>.bak.1 (newest) ..
// <path>.bak.N (oldest); each call shifts them down and writes a fresh .1,
// dropping the oldest. This bounds the SD-card clutter (the previous
// ".bak.<YYYYmmdd-HHMMSS>" scheme grew without limit and, with no RTC, two saves
// in the same second silently overwrote each other). A backup whose content is
// byte-identical to the current newest one is skipped, so saves that did not
// actually change the library produce no churn.
static void backup_cheat_library_rolling(const char *srcpath) {
    constexpr int MAX_BACKUPS = 5;
    char patha[260], pathb[260];

    FILE *cur = fopen(srcpath, "rb");
    if (cur == NULL) return;                       // no library on disk yet

    snprintf(patha, sizeof patha, "%s.bak.1", srcpath);
    FILE *prev = fopen(patha, "rb");
    if (prev != NULL) {
        bool identical = false;
        fseek(cur, 0, SEEK_END); long cs = ftell(cur);
        fseek(prev, 0, SEEK_END); long ps = ftell(prev);
        if (cs >= 0 && cs == ps) {
            identical = true;
            rewind(cur); rewind(prev);
            int ca, pa;
            do { ca = fgetc(cur); pa = fgetc(prev); if (ca != pa) { identical = false; break; } } while (ca != EOF);
        }
        fclose(prev);
        if (identical) { fclose(cur); return; }    // library unchanged
    }

    // Shift .bak.(N-1)->.bak.N ... .bak.1->.bak.2; oldest is dropped.
    for (int k = MAX_BACKUPS - 1; k >= 1; k--) {
        snprintf(patha, sizeof patha, "%s.bak.%d", srcpath, k);
        snprintf(pathb, sizeof pathb, "%s.bak.%d", srcpath, k + 1);
        rename(patha, pathb);                       // missing source: harmless fail
    }

    snprintf(patha, sizeof patha, "%s.bak.1", srcpath);
    FILE *dst = fopen(patha, "wb");
    if (dst != NULL) {
        char buf[4096]; size_t n;
        rewind(cur);
        while ((n = fread(buf, 1, sizeof buf, cur)) > 0) {
            if (fwrite(buf, 1, n, dst) != n) break;
        }
        fclose(dst);
    }
    fclose(cur);
}

void dumpcodetofile() {
    FILE *pfile;
    char tmp[1000];
    if (build_id[0] == 0x0 && build_id[1] == 0x0 && build_id[2] == 0x0 && build_id[3] == 0x0 && build_id[4] == 0x0 && build_id[5] == 0x0 && build_id[6] == 0x0 && build_id[7])
        return;
    snprintf(m_cheatcode_path, 128, "sdmc:/atmosphere/contents/%016lX/cheats/%02X%02X%02X%02X%02X%02X%02X%02X.txt", metadata.title_id, build_id[0], build_id[1], build_id[2], build_id[3], build_id[4], build_id[5], build_id[6], build_id[7]);
    snprintf(m_toggle_path, 128, "sdmc:/atmosphere/contents/%016lX/cheats/toggles.txt", metadata.title_id);
    // Last-resort safety net before the .txt library is truncated and rewritten:
    // roll a bounded set of backups (see backup_cheat_library_rolling). Deleting a
    // cheat here is otherwise unrecoverable, so keep a restore point.
    backup_cheat_library_rolling(m_cheatcode_path);
    pfile = fopen(m_cheatcode_path, "w");
    if (pfile != NULL) {
        snprintf(tmp, 1000, "[Zing %s %s %s TID: %016lX BID: %02X%02X%02X%02X%02X%02X%02X%02X]\n\n", VERSION, m_titleName.c_str(), m_versionString.c_str(), metadata.title_id,
                 build_id[0], build_id[1], build_id[2], build_id[3], build_id[4], build_id[5], build_id[6], build_id[7]);
        fputs(tmp, pfile);
        for (u32 i = 0; i < m_cheatCnt; i++) {
            // output outlines
            if (m_outline.size() > 1) {
                tmp[0] = 0;
                for (auto entry : m_outline) {
                    if (entry.index > i) break;
                    if (entry.index == i) snprintf(tmp, sizeof tmp, "[%s]\n", entry.label.c_str());
                }
                if (strlen(tmp) > 0) fputs(tmp, pfile);
            }

            // NOTE: master code is registered separately via dmntchtSetMasterCheat and
            // never appears in m_cheats (dmntchtGetCheats only returns regular cheats).
            // Always dump as a regular [name] block; previously the first entry was
            // wrongly emitted as {name} which turned it into a master code on reload
            // and made it impossible to disable from the UI.
            snprintf(tmp, 1000, "[%s]\n", m_cheats[i].definition.readable_name);
            fputs(tmp, pfile);
            for (u32 j = 0; j < m_cheats[i].definition.num_opcodes; j++) {
                u16 opcode = (m_cheats[i].definition.opcodes[j] >> 28) & 0xF;
                u8 T = (m_cheats[i].definition.opcodes[j] >> 24) & 0xF;
                if ((opcode == 9) && (((m_cheats[i].definition.opcodes[j] >> 8) & 0xF) == 0)) {
                    snprintf(tmp, 1000, "%08X\n", m_cheats[i].definition.opcodes[j]);
                    fputs(tmp, pfile);
                    continue;
                }
                if (opcode == 0xC) {
                    opcode = (m_cheats[i].definition.opcodes[j] >> 24) & 0xFF;
                    T = (m_cheats[i].definition.opcodes[j] >> 20) & 0xF;
                    u8 X = (m_cheats[i].definition.opcodes[j] >> 8) & 0xF;
                    if (opcode == 0xC0) {
                        opcode = opcode * 16 + X;
                    }
                }
                if (opcode == 10) {
                    u8 O = (m_cheats[i].definition.opcodes[j] >> 8) & 0xF;
                    if (O == 2 || O == 4 || O == 5)
                        T = 8;
                    else
                        T = 4;
                }
                switch (opcode) {
                    case 0:
                    case 1:
                        snprintf(tmp, sizeof(tmp), "%08X ", m_cheats[i].definition.opcodes[j++]);
                        fputs(tmp, pfile);
                        // 3+1: intentionally cascades to emit the operand words
                        [[fallthrough]];
                    case 9:
                    case 0xC04:
                        // 2+1
                        snprintf(tmp, sizeof(tmp), "%08X ", m_cheats[i].definition.opcodes[j++]);
                        fputs(tmp, pfile);
                        [[fallthrough]]; // cascade into the 1+1 group
                    case 3:
                    case 10:
                        // 1+1
                        snprintf(tmp, sizeof(tmp), "%08X ", m_cheats[i].definition.opcodes[j]);
                        fputs(tmp, pfile);
                        if (T == 8 || (T == 0 && opcode == 3)) {
                            j++;
                            snprintf(tmp, sizeof(tmp), "%08X ", m_cheats[i].definition.opcodes[j]);
                            fputs(tmp, pfile);
                        }
                        break;
                    case 4:
                    case 6:
                        // 3
                        snprintf(tmp, sizeof(tmp), "%08X ", m_cheats[i].definition.opcodes[j++]);
                        fputs(tmp, pfile);
                        [[fallthrough]]; // 4/6 share their tail with 5/7/...
                    case 5:
                    case 7:
                    case 0xC00:
                    case 0xC02:
                        snprintf(tmp, sizeof(tmp), "%08X ", m_cheats[i].definition.opcodes[j++]);
                        fputs(tmp, pfile);
                        // 2
                        [[fallthrough]]; // cascade into the single-word group
                    case 2:
                    case 8:
                    case 0xC1:
                    case 0xC2:
                    case 0xC3:
                    case 0xC01:
                    case 0xC03:
                    case 0xC05:
                    default:
                        snprintf(tmp, sizeof(tmp), "%08X ", m_cheats[i].definition.opcodes[j]);
                        fputs(tmp, pfile);
                        // 1
                        break;
                }
                if (j >= (m_cheats[i].definition.num_opcodes))  // better to be ugly than to corrupt
                {
                    for (u32 k = 0; k < m_cheats[i].definition.num_opcodes; k++) {
                        snprintf(tmp, sizeof(tmp), "%08X ", m_cheats[i].definition.opcodes[k++]);
                        fputs(tmp, pfile);
                    }
                    snprintf(tmp, sizeof(tmp), "\n");
                    fputs(tmp, pfile);
                    break;
                }
                snprintf(tmp, sizeof(tmp), "\n");
                fputs(tmp, pfile);
            }
            snprintf(tmp, sizeof(tmp), "\n");
            fputs(tmp, pfile);
        }
        fclose(pfile);
    }
}

// Self-describing header written at the start of the .bz1 data region.
// Previously the loader guessed the record layout purely from the file size,
// which is ambiguous (9 legacy 8-byte records == 1 modern 72-byte record).
// A magic + explicit stride removes all guesswork going forward, while the
// legacy size-heuristic path is kept for files written before this header.
struct bz_header_t {
    u32 magic;   // BZ_TOGGLE_MAGIC
    u32 stride;  // sizeof(toggle_list_t) at save time
    u32 count;   // number of records that follow
};
static constexpr u32 BZ_TOGGLE_MAGIC = 0x5A54312D; // "ZT1-"

void save_breeze_toggle() {
    std::string breeze_toggle_filename = bookmarkfilename;
    breeze_toggle_filename.replace((breeze_toggle_filename.length()-3), 3, "bz1");
    std::unique_ptr<MemoryDump> breeze_toggle_file =
        std::make_unique<MemoryDump>(breeze_toggle_filename.c_str(), DumpType::ADDR, true);
    bz_header_t hdr = {};
    hdr.magic = BZ_TOGGLE_MAGIC;
    hdr.stride = (u32)sizeof(toggle_list_t);
    hdr.count = (u32)m_toggle_list.size();
    breeze_toggle_file->addData((u8 *)&hdr, sizeof(hdr));
    for (const auto &entry : m_toggle_list) {
        breeze_toggle_file->addData((u8 *)&entry, sizeof(toggle_list_t));
    }
}

void load_breeze_toggle() {
    m_toggle_list.clear();
    std::string breeze_toggle_filename = bookmarkfilename;
    breeze_toggle_filename.replace((breeze_toggle_filename.length()-3), 3, "bz1");
    std::unique_ptr<MemoryDump> breeze_toggle_file =
        std::make_unique<MemoryDump>(breeze_toggle_filename.c_str(), DumpType::ADDR, false);
    size_t file_size = breeze_toggle_file->size();
    if (file_size == 0)
        return;

    constexpr size_t NEW_STRIDE = sizeof(toggle_list_t);
    // Layout of the pre-name struct (keycode + cheat_id only).
    constexpr size_t OLD_STRIDE = sizeof(u32) * 2;

    // Try to read the self-describing header first. New saves always write it,
    // so a matching magic means the records follow at the declared stride. A
    // count of 0 is valid (empty toggle list) and must NOT fall through to the
    // legacy reader, which would misinterpret the 12-byte header as a record.
    bz_header_t hdr = {};
    breeze_toggle_file->getData(0, &hdr, sizeof(hdr));
    if (hdr.magic == BZ_TOGGLE_MAGIC && hdr.stride >= OLD_STRIDE &&
        (sizeof(hdr) + (size_t)hdr.count * hdr.stride) <= file_size) {
        for (u32 i = 0; i < hdr.count; i++) {
            toggle_list_t entry = {};
            // Read only the smaller of stored/struct stride; missing trailing
            // bytes (e.g. name for a future larger stride) stay zero-init.
            size_t rec = std::min<size_t>(hdr.stride, NEW_STRIDE);
            breeze_toggle_file->getData(sizeof(hdr) + (size_t)i * hdr.stride, &entry, rec);
            entry.name[sizeof(entry.name) - 1] = 0;
            m_toggle_list.push_back(entry);
        }
        return;
    }

    // ---- Legacy path ----
    // A headerless file was necessarily written before the self-describing
    // header existed, i.e. before toggle_list_t gained the name field, so EVERY
    // record uses the old 8-byte (keycode + cheat_id) layout. (The previous
    // size-heuristic here misread headerless files whose byte length happened to
    // be a multiple of the new 72-byte stride, e.g. 9/18/27 stored toggles.)
    // ReconcileToggleList() back-fills the name from the cheat_id once m_cheats
    // is populated.
    for (size_t off = 0; off + OLD_STRIDE <= file_size; off += OLD_STRIDE) {
        toggle_list_t entry = {};   // zero-init leaves name empty
        breeze_toggle_file->getData(off, &entry, OLD_STRIDE);
        m_toggle_list.push_back(entry);
    }
}

void save_breeze_action() {
    std::string breeze_action_filename = bookmarkfilename;
    breeze_action_filename.replace((breeze_action_filename.length()-3), 3, "bz2");
    std::unique_ptr<MemoryDump> breeze_acton_file =
        std::make_unique<MemoryDump>(breeze_action_filename.c_str(), DumpType::ADDR, true);
    for (const auto &entry : m_breeze_action_list) {
        breeze_acton_file->addData((u8 *)&entry, sizeof(breeze_action_list_t));
    }
}

void load_breeze_action() {
    m_breeze_action_list.clear();
    std::string breeze_action_filename = bookmarkfilename;
    breeze_action_filename.replace((breeze_action_filename.length()-3), 3, "bz2");
    std::unique_ptr<MemoryDump> breeze_acton_file =
        std::make_unique<MemoryDump>(breeze_action_filename.c_str(), DumpType::ADDR, false);
    breeze_action_list_t entry;
    if (breeze_acton_file->size() > 0)
        for (size_t i = 0; i < breeze_acton_file->size() / sizeof(breeze_action_list_t); i++) {
            breeze_acton_file->getData(i * sizeof(breeze_action_list_t), &entry, sizeof(breeze_action_list_t));
            m_breeze_action_list.push_back(entry);
        }
}

bool loadcachefromfile() {
    if (build_id[0] == 0x0 && build_id[1] == 0x0 && build_id[2] == 0x0 && build_id[3] == 0x0 && build_id[4] == 0x0 && build_id[5] == 0x0 && build_id[6] == 0x0 && build_id[7])
        return false;

    m_cache_outline.clear();
    m_cache.clear();
    u32 _index = 0;
    bool copy_cheat_file = false;

    snprintf(m_cheatcode_path, 128, "sdmc:/switch/EdiZon/%02X%02X%02X%02X%02X%02X%02X%02X.txt", build_id[0], build_id[1], build_id[2], build_id[3], build_id[4], build_id[5], build_id[6], build_id[7]);
    // if (access(m_cheatcode_path, F_OK) != 0)
    FILE *pfile, *pfile2 = NULL;
    pfile = fopen(m_cheatcode_path, "rb");
    if (pfile == NULL) {
        char atm_path[128];
        snprintf(atm_path, 128, "sdmc:/atmosphere/contents/%016lX/cheats/%02X%02X%02X%02X%02X%02X%02X%02X.txt", metadata.title_id, build_id[0], build_id[1], build_id[2], build_id[3], build_id[4], build_id[5], build_id[6], build_id[7]);
        pfile = fopen(atm_path, "rb");
        copy_cheat_file = true;
    }
    if (pfile != NULL) {
        fseek(pfile, 0, SEEK_END);
        long fileLen = ftell(pfile);
        if (fileLen < 0 || static_cast<size_t>(fileLen) > CHEAT_FILE_MAX_LEN) {
            fclose(pfile);
            return false;
        }
        size_t len = static_cast<size_t>(fileLen);
        // Owned buffer: every parse error below returns early, so the raw
        // `new u8[len]` leaked the whole file on all those paths.
        std::unique_ptr<u8[]> s(new u8[len]);
        fseek(pfile, 0, SEEK_SET);
        fread(s.get(), 1, len, pfile);
        fclose(pfile); 
        if (copy_cheat_file) {
            pfile2 = fopen(m_cheatcode_path, "wb");
            if (pfile2 != NULL) {
                fwrite(s.get(), 1, len, pfile2);
                fclose(pfile2);
            }
        }
        DmntCheatEntry cheatentry;
        cheatentry.definition.num_opcodes = 0;
        cheatentry.enabled = false;
        u8 label_len = 0;
        size_t i = 0;
        cache_outline_t entry = {};
        while (i < len) {
            if (std::isspace(static_cast<unsigned char>(s[i]))) {
                /* Just ignore whitespace. */
                i++;
            } else if (s[i] == '[') {
                if (cheatentry.definition.num_opcodes != 0) {
                    if (cheatentry.definition.opcodes[0] == 0x20000000) {
                        if (entry.is_outline) {
                            entry.size = _index - entry.index -1;
                            m_cache_outline.push_back(entry);
                        }
                        entry.index = _index;
                        entry.expanded = false;
                        entry.always_expanded = false;
                        entry.label = cheatentry.definition.readable_name;
                        entry.is_outline = true;
                    }
                    // if (cheatentry.enabled == true)
                    //     // dmntchtSetMasterCheat(&(cheatentry.definition));
                    // else
                        m_cache.push_back(cheatentry);
                        // dmntchtAddCheat(&(cheatentry.definition), cheatentry.enabled, &(cheatentry.cheat_id));
                    _index++;
                } 
                cheatentry.definition.num_opcodes = 0;
                cheatentry.enabled = false;
                /* Extract name bounds. */
                size_t j = i + 1;
                if (j >= len) return false;
                while (s[j] != ']') {
                    j++;
                    if (j >= len) {
                        return false;
                    }
                }
                /* s[i+1:j] is cheat name. */
                // Reserve the final byte for the NUL terminator: the old
                // bound used sizeof(readable_name), so the worst-case
                // readable_name[cheat_name_len] = 0 wrote one past the array.
                const size_t cheat_name_len = std::min(j - i - 1, sizeof(cheatentry.definition.readable_name) - 1);
                std::memcpy(cheatentry.definition.readable_name, &s[i + 1], cheat_name_len);
                for (u32 cc = 0; cc < cheat_name_len; cc++) {
                    if (cheatentry.definition.readable_name[cc] == 13 || cheatentry.definition.readable_name[cc] == 10) cheatentry.definition.readable_name[cc] = 32;
                };
                cheatentry.definition.readable_name[cheat_name_len] = 0;
                label_len = cheat_name_len;

                /* Skip onwards. */
                i = j + 1;
            } else if (s[i] == '(') {
                size_t j = i + 1;
                if (j >= len) return false;
                while (s[j] != ')') {
                    j++;
                    if (j >= len) {
                        return false;
                    }
                }
                i = j + 1;
            } else if (s[i] == '{') {
                if (cheatentry.definition.num_opcodes != 0) {
                    m_cache.push_back(cheatentry);
                    _index++;
                    // dmntchtAddCheat(&(cheatentry.definition), cheatentry.enabled, &(cheatentry.cheat_id));
                }
                /* We're parsing a master cheat. Turn it on */
                cheatentry.definition.num_opcodes = 0;
                cheatentry.enabled = true;
                /* Extract name bounds */
                size_t j = i + 1;
                if (j >= len) return false;
                while (s[j] != '}') {
                    j++;
                    if (j >= len) {
                        return false;
                    }
                }

                /* s[i+1:j] is cheat name. */
                // Reserve the final byte for the NUL terminator (same bound as
                // the '[' branch above); the old sizeof() let the worst-case
                // readable_name[cheat_name_len] = 0 write one past the array.
                const size_t cheat_name_len = std::min(j - i - 1, sizeof(cheatentry.definition.readable_name) - 1);
                memcpy(cheatentry.definition.readable_name, &s[i + 1], cheat_name_len);
                cheatentry.definition.readable_name[cheat_name_len] = 0;
                label_len = cheat_name_len;
                // strcpy(cheatentry.definition.readable_name, "master code");

                /* Skip onwards. */
                i = j + 1;
            } else if (std::isxdigit(static_cast<unsigned char>(s[i]))) {
                if (label_len == 0)
                    return false;
                /* Bounds check the opcode count. */
                if (cheatentry.definition.num_opcodes >= sizeof(cheatentry.definition.opcodes) / 4) {
                    if (cheatentry.definition.num_opcodes != 0) {
                        m_cache.push_back(cheatentry);
                        // dmntchtAddCheat(&(cheatentry.definition), cheatentry.enabled, &(cheatentry.cheat_id));
                    }
                    return false;
                }

                /* We're parsing an instruction, so validate it's 8 hex digits. */
                for (size_t j = 1; j < 8; j++) {
                    /* Validate 8 hex chars. */
                    if (i + j >= len || !std::isxdigit(static_cast<unsigned char>(s[i + j]))) {
                        if (cheatentry.definition.num_opcodes != 0) {
                            m_cache.push_back(cheatentry);
                            // dmntchtAddCheat(&(cheatentry.definition), cheatentry.enabled, &(cheatentry.cheat_id));
                        }
                        return false;
                    }
                }

                /* Parse the new opcode. */
                char hex_str[9] = {0};
                std::memcpy(hex_str, &s[i], 8);
                cheatentry.definition.opcodes[cheatentry.definition.num_opcodes++] = std::strtoul(hex_str, NULL, 16);

                /* Skip onwards. */
                i += 8;
            } else {
                /* Unexpected character encountered. */
                if (cheatentry.definition.num_opcodes != 0) {
                    m_cache.push_back(cheatentry);
                    // dmntchtAddCheat(&(cheatentry.definition), cheatentry.enabled, &(cheatentry.cheat_id));
                }
                return false;
            }
        }
        if (cheatentry.definition.num_opcodes != 0) {
            m_cache.push_back(cheatentry);
            // dmntchtAddCheat(&(cheatentry.definition), cheatentry.enabled, &(cheatentry.cheat_id));
        }
        if (entry.is_outline) {
            entry.size = _index - entry.index - 1;
            m_cache_outline.push_back(entry);
        }
        return true;
    } else {
        cache_outline_t entry = {};
        DmntCheatEntry centry = {};
        // Bound the error message to the destination field: the old
        // strcat(m_cheatcode_path[128], ...) followed by
        // strcpy(readable_name[0x40], path) could overflow both buffers when the
        // localized suffix pushed the path past the field size.
        std::string failMsg = std::string(m_cheatcode_path) + "LoadFailedLoadCacheFromFileDmntCheatEntryText"_tr;
        size_t n = failMsg.size();
        if (n > sizeof(centry.definition.readable_name) - 1)
            n = sizeof(centry.definition.readable_name) - 1;
        std::memcpy(centry.definition.readable_name, failMsg.data(), n);
        centry.definition.readable_name[n] = 0;
        m_cache.push_back(centry);
        m_cache_outline.push_back(entry);
    }
    return false;
}

bool loadcheatsfromfile() {
    if (build_id[0] == 0x0 && build_id[1] == 0x0 && build_id[2] == 0x0 && build_id[3] == 0x0 && build_id[4] == 0x0 && build_id[5] == 0x0 && build_id[6] == 0x0 && build_id[7])
        return false;

    m_outline.clear();
    u32 _index = 0;
    u32 last_entry = 0xFFFFFFFFu;

    snprintf(m_cheatcode_path, 128, "sdmc:/atmosphere/contents/%016lX/cheats/%02X%02X%02X%02X%02X%02X%02X%02X.txt", metadata.title_id, build_id[0], build_id[1], build_id[2], build_id[3], build_id[4], build_id[5], build_id[6], build_id[7]);
    
    FILE *pfile;
    pfile = fopen(m_cheatcode_path, "rb");
    if (pfile == NULL) {
        char zing_path[128];
        snprintf(zing_path, 128, "sdmc:/switch/EdiZon/%02X%02X%02X%02X%02X%02X%02X%02X.txt", build_id[0], build_id[1], build_id[2], build_id[3], build_id[4], build_id[5], build_id[6], build_id[7]);
        pfile = fopen(zing_path, "rb");
    }
    if (pfile != NULL) {
        fseek(pfile, 0, SEEK_END);
        long fileLen = ftell(pfile);
        if (fileLen < 0 || static_cast<size_t>(fileLen) > CHEAT_FILE_MAX_LEN) {
            fclose(pfile);
            return false;
        }
        size_t len = static_cast<size_t>(fileLen);
        // Owned buffer: every parse error below returns early, so the raw
        // `new u8[len]` leaked the whole file on all those paths.
        std::unique_ptr<u8[]> s(new u8[len]);
        fseek(pfile, 0, SEEK_SET);
        fread(s.get(), 1, len, pfile);
        fclose(pfile);
        DmntCheatEntry cheatentry;
        cheatentry.definition.num_opcodes = 0;
        cheatentry.enabled = false;
        u8 label_len = 0;
        size_t i = 0;
        while (i < len) {
            if (std::isspace(static_cast<unsigned char>(s[i]))) {
                /* Just ignore whitespace. */
                i++;
            } else if (s[i] == '[') {
                if (cheatentry.definition.num_opcodes != 0) {
                    if (cheatentry.definition.opcodes[0] == 0x20000000) {
                        outline_t entry;
                        entry.index = _index;
                        entry.label = cheatentry.definition.readable_name;
                        if (label_len > 0) {
                            if (last_entry == _index) m_outline.pop_back();
                            m_outline.push_back(entry);
                            last_entry = _index;
                        }
                    }
                    if (cheatentry.enabled == true)
                        dmntchtSetMasterCheat(&(cheatentry.definition));
                    else
                        dmntchtAddCheat(&(cheatentry.definition), cheatentry.enabled, &(cheatentry.cheat_id));
                    _index++;
                } 
                cheatentry.definition.num_opcodes = 0;
                cheatentry.enabled = false;
                /* Extract name bounds. */
                size_t j = i + 1;
                if (j >= len) return false;
                while (s[j] != ']') {
                    j++;
                    if (j >= len) {
                        return false;
                    }
                }
                /* s[i+1:j] is cheat name. */
                // Reserve the final byte for the NUL terminator: the old
                // bound used sizeof(readable_name), so the worst-case
                // readable_name[cheat_name_len] = 0 wrote one past the array.
                const size_t cheat_name_len = std::min(j - i - 1, sizeof(cheatentry.definition.readable_name) - 1);
                std::memcpy(cheatentry.definition.readable_name, &s[i + 1], cheat_name_len);
                for (u32 cc = 0; cc < cheat_name_len; cc++) {
                    if (cheatentry.definition.readable_name[cc] == 13 || cheatentry.definition.readable_name[cc] == 10) cheatentry.definition.readable_name[cc] = 32;
                };
                cheatentry.definition.readable_name[cheat_name_len] = 0;
                label_len = cheat_name_len;

                /* Skip onwards. */
                i = j + 1;
            } else if (s[i] == '(') {
                size_t j = i + 1;
                if (j >= len) return false;
                while (s[j] != ')') {
                    j++;
                    if (j >= len) {
                        return false;
                    }
                }
                i = j + 1;
            } else if (s[i] == '{') {
                if (cheatentry.definition.num_opcodes != 0) {
                    dmntchtAddCheat(&(cheatentry.definition), cheatentry.enabled, &(cheatentry.cheat_id));
                }
                /* We're parsing a master cheat. Turn it on */
                cheatentry.definition.num_opcodes = 0;
                cheatentry.enabled = true;
                /* Extract name bounds */
                size_t j = i + 1;
                if (j >= len) return false;
                while (s[j] != '}') {
                    j++;
                    if (j >= len) {
                        return false;
                    }
                }

                /* s[i+1:j] is cheat name. */
                // Reserve the final byte for the NUL terminator (same bound as
                // the '[' branch above); the old sizeof() let the worst-case
                // readable_name[cheat_name_len] = 0 write one past the array.
                const size_t cheat_name_len = std::min(j - i - 1, sizeof(cheatentry.definition.readable_name) - 1);
                memcpy(cheatentry.definition.readable_name, &s[i + 1], cheat_name_len);
                cheatentry.definition.readable_name[cheat_name_len] = 0;
                label_len = cheat_name_len;
                // strcpy(cheatentry.definition.readable_name, "master code");

                /* Skip onwards. */
                i = j + 1;
            } else if (std::isxdigit(static_cast<unsigned char>(s[i]))) {
                if (label_len == 0)
                    return false;
                /* Bounds check the opcode count. */
                if (cheatentry.definition.num_opcodes >= sizeof(cheatentry.definition.opcodes) / 4) {
                    if (cheatentry.definition.num_opcodes != 0) {
                        dmntchtAddCheat(&(cheatentry.definition), cheatentry.enabled, &(cheatentry.cheat_id));
                    }
                    return false;
                }

                /* We're parsing an instruction, so validate it's 8 hex digits. */
                for (size_t j = 1; j < 8; j++) {
                    /* Validate 8 hex chars. */
                    if (i + j >= len || !std::isxdigit(static_cast<unsigned char>(s[i + j]))) {
                        if (cheatentry.definition.num_opcodes != 0) {
                            dmntchtAddCheat(&(cheatentry.definition), cheatentry.enabled, &(cheatentry.cheat_id));
                        }
                        return false;
                    }
                }

                /* Parse the new opcode. */
                char hex_str[9] = {0};
                std::memcpy(hex_str, &s[i], 8);
                cheatentry.definition.opcodes[cheatentry.definition.num_opcodes++] = std::strtoul(hex_str, NULL, 16);

                /* Skip onwards. */
                i += 8;
            } else {
                /* Unexpected character encountered. */
                if (cheatentry.definition.num_opcodes != 0) {
                    dmntchtAddCheat(&(cheatentry.definition), cheatentry.enabled, &(cheatentry.cheat_id));
                }
                return false;
            }
        }
        if (cheatentry.definition.num_opcodes != 0) {
            dmntchtAddCheat(&(cheatentry.definition), cheatentry.enabled, &(cheatentry.cheat_id));
        }
        return true;
    }
    return false;
}

DmntCheatEntry *GetCheatEntryByReadableName(const char *readable_name) {
    /* Check all non-master cheats for match. */
    for (size_t i = 0; i < m_cheatCnt; i++) {
        if (std::strncmp(m_cheats[i].definition.readable_name, readable_name, sizeof(m_cheats[i].definition.readable_name)) == 0) {
            return &m_cheats[i];
        }
    }
    return nullptr;
}

// Resolve the live dmnt cheat_id for a cheat identified by its readable name.
// Returns true and writes the id to *out_id on a match; returns false when no
// current cheat carries the name. dmnt does not forbid duplicate readable_name,
// so when *ambiguous (if provided) is set true the name matches more than one
// cheat and the caller must NOT trust the single id -- it should fall back to the
// per-entry stored cheat_id, otherwise every same-named toggle would collapse onto
// the first match and the others could never be switched off.
static bool LookupCheatIdByName(const char *name, u32 *out_id, bool *ambiguous = nullptr) {
    if (name == nullptr || name[0] == 0 || out_id == nullptr) return false;
    u32 matches = 0;
    u32 first_id = 0;
    for (u32 i = 0; i < m_cheatCnt; i++) {
        if (m_cheats == nullptr) break;
        if (std::strncmp(m_cheats[i].definition.readable_name, name,
                         sizeof(m_cheats[i].definition.readable_name)) == 0) {
            if (matches == 0) first_id = m_cheats[i].cheat_id;
            matches++;
        }
    }
    if (ambiguous != nullptr) *ambiguous = (matches > 1);
    if (matches == 0) return false;
    *out_id = first_id;
    return true;
}

// Reconcile the cached cheat_id values in m_toggle_list against the live dmnt
// cheat list. Older .bz1 files were written before name was a persisted field,
// so for legacy entries we back-fill the name from the cheat_id when it still
// matches. For modern entries we always refresh cheat_id by name lookup.
static void ReconcileToggleList() {
    if (m_cheats == nullptr) return;
    for (auto &e : m_toggle_list) {
        // Legacy entry without persisted name: try to recover it from cheat_id.
        if (e.name[0] == 0) {
            for (u32 i = 0; i < m_cheatCnt; i++) {
                if (m_cheats[i].cheat_id == e.cheat_id) {
                    std::memcpy(e.name, m_cheats[i].definition.readable_name, sizeof(e.name));
                    e.name[sizeof(e.name) - 1] = 0;
                    break;
                }
            }
        }
        // Re-resolve cheat_id by name so subsequent toggles hit the right entry.
        // Skip the overwrite when the name is shared by several cheats: collapsing
        // them onto the first match would make the duplicates un-toggleable, so we
        // keep the stored cheat_id (correct per-entry for freshly assigned combos).
        u32 live_id = 0;
        bool ambiguous = false;
        if (LookupCheatIdByName(e.name, &live_id, &ambiguous)) {
            if (!ambiguous) e.cheat_id = live_id;
        }
    }
}

bool ParseCheatToggles(const char *s, size_t len) {
    if (s == nullptr || len == 0) return false;
    size_t i = 0;
    char cur_cheat_name[sizeof(DmntCheatDefinition::readable_name)];
    char toggle[8];
    while (i < len) {
        if (std::isspace(static_cast<unsigned char>(s[i]))) {
            /* Just ignore whitespace. */
            i++;
        } else if (s[i] == '[') {
            /* Extract name bounds. */
            size_t j = i + 1;
            /* Bounds check before the first read to avoid OOB when input
             * ends with '['. */
            if (j >= len) return false;
            while (s[j] != ']') {
                j++;
                if (j >= len) {
                    return false;
                }
            }
            /* s[i+1:j] is cheat name. */
            const size_t cheat_name_len = std::min(j - i - 1, sizeof(cur_cheat_name) - 1);
            std::memcpy(cur_cheat_name, &s[i + 1], cheat_name_len);
            cur_cheat_name[cheat_name_len] = 0;
            /* Skip onwards. */
            i = j + 1;
            if (i >= len) return false;
            /* Skip whitespace. */
            while (i < len && std::isspace(static_cast<unsigned char>(s[i]))) {
                i++;
            }
            if (i >= len) return false;
            /* Parse whether to toggle. */
            j = i + 1;
            /* Bounds check before the first read so a one-char toggle at
             * end-of-buffer (e.g. "1") does not read s[len]. */
            if (j >= len) {
                /* Toggle value is exactly one character at end of file. */
                const size_t toggle_len = 1;
                std::memcpy(toggle, &s[i], toggle_len);
                toggle[toggle_len] = 0;
                j = i + 1;
            } else {
                while (!std::isspace(static_cast<unsigned char>(s[j]))) {
                    j++;
                    if (j >= len || (j - i) >= sizeof(toggle)) {
                        return false;
                    }
                }
                /* s[i:j] is toggle. */
                const size_t toggle_len = (j - i);
                std::memcpy(toggle, &s[i], toggle_len);
                toggle[toggle_len] = 0;
            }
            /* Allow specifying toggle for not present cheat. */
            DmntCheatEntry *entry = GetCheatEntryByReadableName(cur_cheat_name);
            if (entry != nullptr) {
                if (strcasecmp(toggle, "1") == 0 || strcasecmp(toggle, "true") == 0 || strcasecmp(toggle, "on") == 0) {
                    if (entry->enabled != true) dmntchtToggleCheat(entry->cheat_id);
                    entry->enabled = true;
                } else if (strcasecmp(toggle, "0") == 0 || strcasecmp(toggle, "false") == 0 || strcasecmp(toggle, "off") == 0) {
                    if (entry->enabled != false) dmntchtToggleCheat(entry->cheat_id);
                    entry->enabled = false;
                }
            }
            /* Skip onwards. */
            i = j + 1;
        } else {
            /* Unexpected character encountered. */
            return false;
        }
    }
    return true;
}

void loadtoggles() {
    snprintf(m_toggle_path, 128, "sdmc:/atmosphere/contents/%016lX/cheats/toggles.brz", metadata.title_id);
    FILE *pfile;
    pfile = fopen(m_toggle_path, "rb");
    if (pfile != NULL) {
        fseek(pfile, 0, SEEK_END);
        long fileLen = ftell(pfile);
        // Treat a failed ftell() or an over-long file as "nothing to parse"
        // rather than allocating based on a garbage length.
        size_t len = (fileLen < 0 || static_cast<size_t>(fileLen) > CHEAT_FILE_MAX_LEN)
                         ? 0 : static_cast<size_t>(fileLen);
        if (len > 0) {
            char *s = new char[len];
            fseek(pfile, 0, SEEK_SET);
            size_t rd = fread(s, 1, len, pfile);
            ParseCheatToggles(s, rd);
            delete[] s;
        }
        fclose(pfile);
    }
}

void savetoggles() {
    snprintf(m_toggle_path, 128, "sdmc:/atmosphere/contents/%016lX/cheats/toggles.brz", metadata.title_id);
    FILE *pfile;
    char tmp[1000];
    pfile = fopen(m_toggle_path, "w");
    if (pfile != NULL) {
        // m_cheatCnt is u64; an u8 loop index would silently truncate past
        // 255 entries (MaxCheatCount is 0x80 today, but the type mismatch is
        // a footgun). Use u32 to match dmnt API conventions.
        for (u32 i = 0; i < (u32)m_cheatCnt; i++) {
            snprintf(tmp, 1000, "[%s]\n%s\n", m_cheats[i].definition.readable_name, (m_cheats[i].enabled) ? "true" : "false");
            fputs(tmp, pfile);
        }
        fclose(pfile);
    }
}

static std::string _getAddressDisplayString(u64 address, Debugger *debugger, searchType_t searchType) {
    // Pre-initialize so the SEARCH_TYPE_NONE fall-through path still returns
    // a deterministic empty string instead of uninitialized stack bytes.
    char ss[200] = "";

    searchValue_t searchValue;
    searchValue._u64 = debugger->peekMemory(address);
    {
        switch (searchType) {
            case SEARCH_TYPE_UNSIGNED_8BIT:
                snprintf(ss, sizeof ss, "%d", searchValue._u8);
                break;
            case SEARCH_TYPE_UNSIGNED_16BIT:
                snprintf(ss, sizeof ss, "%d", searchValue._u16);
                break;
            case SEARCH_TYPE_UNSIGNED_32BIT:
                snprintf(ss, sizeof ss, "%d", searchValue._u32);
                break;
            case SEARCH_TYPE_UNSIGNED_64BIT:
                snprintf(ss, sizeof ss, "0x%016lX", searchValue._u64);
                break;
            case SEARCH_TYPE_SIGNED_8BIT:
                snprintf(ss, sizeof ss, "%d", searchValue._s8);
                break;
            case SEARCH_TYPE_SIGNED_16BIT:
                snprintf(ss, sizeof ss, "%d", searchValue._s16);
                break;
            case SEARCH_TYPE_SIGNED_32BIT:
                snprintf(ss, sizeof ss, "%d", searchValue._s32);
                break;
            case SEARCH_TYPE_SIGNED_64BIT:
                snprintf(ss, sizeof ss, "%ld", searchValue._s64);
                break;
            case SEARCH_TYPE_FLOAT_32BIT:
                snprintf(ss, sizeof ss, "%.2f", searchValue._f32);
                break;
            case SEARCH_TYPE_FLOAT_64BIT:
                snprintf(ss, sizeof ss, "%.2lf", searchValue._f64);
                break;
            case SEARCH_TYPE_POINTER:
                snprintf(ss, sizeof ss, "0x%010lX", searchValue._u64);
                break;
            case SEARCH_TYPE_NONE:
                break;
        }
    }

    return ss;
}

bool deletebookmark() {
    std::string old_bookmarkfilename = bookmarkfilename;
    bookmark_t bookmark;
    // Nothing stored yet -> nothing to delete. Bail before touching files
    // (the old code would still rewrite an empty dump and a stale `.old`).
    size_t bookmark_count = m_AttributeDumpBookmark->size() / sizeof(bookmark_t);
    if (bookmark_count == 0) return false;
    // The row under the cursor must be a real entry; otherwise the
    // `i != target` filter below matches nothing and silently keeps every
    // bookmark while still rewriting the backing files.
    size_t target = (size_t)m_index + m_addresslist_offset;
    if (target >= bookmark_count) return false;
    old_bookmarkfilename.replace((old_bookmarkfilename.length()-3),3,"old");
    std::unique_ptr<MemoryDump> m_old_AttributeDumpBookmark =
        std::make_unique<MemoryDump>(old_bookmarkfilename.c_str(), DumpType::ADDR, true);
    for (size_t i = 0; i < m_AttributeDumpBookmark->size() / sizeof(bookmark_t); i++) {
        {
            m_AttributeDumpBookmark->getData(i * sizeof(bookmark_t), &bookmark, sizeof(bookmark_t));
            m_old_AttributeDumpBookmark->addData((u8 *)&bookmark, sizeof(bookmark_t));
        }
    }
    // Close the previous bookmark file object BEFORE opening a fresh truncated
    // one. The previous `m_AttributeDumpBookmark = make_unique<...>` form lets the
    // right-hand side construct first ("w+b" truncates the file) and only then
    // runs the old object's destructor, whose flushBuffer/fclose act on the SAME
    // still-open path afterwards. That overlap could leave the pre-delete (full)
    // record set on disk, so a bookmark the user removed reappeared after the
    // overlay process restarted and re-read the .dat. reset() flushes+closed the
    // old handle first, restoring the deterministic delete-then-create order the
    // code used before the RAII migration.
    m_AttributeDumpBookmark.reset();
    m_AttributeDumpBookmark = std::make_unique<MemoryDump>(bookmarkfilename, DumpType::ADDR, true);
    for (size_t i = 0; i < m_old_AttributeDumpBookmark->size() / sizeof(bookmark_t); i++) {
        if (i != target) {
            m_old_AttributeDumpBookmark->getData(i * sizeof(bookmark_t), &bookmark, sizeof(bookmark_t));
            m_AttributeDumpBookmark->addData((u8 *)&bookmark, sizeof(bookmark_t));
        }
    }
    // Force the reduced set to disk now instead of relying on the render loop's
    // size()/the destructor to flush it, so the deletion survives even an abrupt
    // overlay-process teardown.
    m_AttributeDumpBookmark->size();
    return true;
}

// Capacity-safe append. The old code called strncat(dst, src, sizeof dst - 1),
// but strncat's third argument is the maximum number of bytes to append *after
// dst's existing contents*, so with a non-empty dst it happily writes past the
// end of the buffer. That is what corrupted the shared display columns
// (BookmarkLabels / Cursor / MultiplierStr ...) once bookmarks grew the column
// and the whole cheat list was then appended. Always bound by remaining space.
static void SafeCat(char *dst, size_t cap, const char *src) {
    if (dst == nullptr || src == nullptr || cap == 0) return;
    size_t used = 0;
    while (used < cap && dst[used] != '\0') used++;   // bounded, dst stays terminated
    if (used >= cap - 1) return;                       // no room left; keep existing text
    ::strncat(dst, src, cap - used - 1);
}

// Section markers in cheat files come in two flavours and both are honoured:
//   * opcode style: first opcode word 0x20000000 = begin, 0x20000001 = end;
//   * name style : readable_name "--SectionStart:<title>--" /
//                  "--SectionEnd:<title>--" with an all-zero opcode body.
// The name-style markers were previously treated as ordinary (zero-offset)
// cheats, which both defeated the collapse and let a stray "+" bookmark them.
static bool IsSectionBegin(const DmntCheatEntry &e) {
    if (e.definition.num_opcodes > 0 && e.definition.opcodes[0] == 0x20000000)
        return true;
    return std::strncmp(e.definition.readable_name, "--SectionStart", 14) == 0;
}
static bool IsSectionEnd(const DmntCheatEntry &e) {
    if (e.definition.num_opcodes > 0 && e.definition.opcodes[0] == 0x20000001)
        return true;
    return std::strncmp(e.definition.readable_name, "--SectionEnd", 12) == 0;
}
// Title shown on the collapsed group row: text between ':' and the trailing
// "--" for name-style markers, otherwise the cheat's own readable name.
static std::string SectionTitle(const DmntCheatEntry &e) {
    std::string n(e.definition.readable_name);
    size_t c = n.find(':');
    if (c != std::string::npos) {
        std::string t = n.substr(c + 1);
        size_t d = t.rfind("--");
        if (d != std::string::npos) t = t.substr(0, d);
        return t;
    }
    return n;
}
// Ordinal of a cheat among the real (non-marker) cheats, i.e. its position with
// all --SectionStart/--SectionEnd rows removed. Used for the info line so a
// section marker is never "counted as a cheat id". Returns -1 when the index
// itself is a marker (an empty group).
static s32 RealCheatOrdinal(u32 target) {
    s32 ord = -1;
    u32 n = 0;
    for (u32 i = 0; i < m_cheatCnt; i++) {
        if (IsSectionBegin(m_cheats[i]) || IsSectionEnd(m_cheats[i])) continue;
        if (i == target) { ord = (s32)n; break; }
        n++;
    }
    return ord;
}

// Resolve the highlighted row of the flat view to its raw m_cheats index, or
// 0xFFFFFFFF when there is nothing to point at (empty list / stale map).
static inline u32 FlatSelectedRaw() {
    if (m_flat_row_count == 0)
        return 0xFFFFFFFFu;
    u32 row = m_cheat_index;
    if (row >= m_flat_row_count)
        row = m_flat_row_count - 1;
    return m_flat_row_raw[row];
}

bool addbookmark() {
    u32 index = m_cheat_index + m_cheatlist_offset;
    if (m_outline_mode) {
        if (m_cheat_outline.empty()) return false;
        if (index >= m_cheat_outline.size()) index = (u32)m_cheat_outline.size() - 1;
        // The cursor is on a collapsed group header (a --SectionStart marker):
        // it is not a real cheat, so there is nothing meaningful to bookmark.
        if (m_cheat_outline[index].is_outline) return false;
        index = m_cheat_outline[index].index;
    } else {
        // Flat view: resolve the highlighted real cheat through the row map,
        // which already excludes section markers.
        index = FlatSelectedRaw();
        if (index == 0xFFFFFFFFu) return false;
    }
    // Final safety net: never index m_cheats[] past its allocated count.
    if (m_cheats == nullptr || index >= (u32)m_cheatCnt) return false;
    // Never turn a section marker into a bookmark (flat/non-outline mode has no
    // is_outline rows, so guard the underlying cheat here too).
    if (IsSectionBegin(m_cheats[index]) || IsSectionEnd(m_cheats[index])) return false;
    DmntCheatDefinition cheat = m_cheats[index].definition;
    bookmark_t bookmark;
    // Force a NUL-terminated copy: cheat.readable_name is 0x40 bytes and
    // bookmark.label is only 19 bytes. Without explicit termination a name
    // that fills the buffer makes downstream snprintf/"%s" reads run past
    // label[] into the rest of bookmark_t.
    std::memcpy(bookmark.label, cheat.readable_name, sizeof(bookmark.label) - 1);
    // Trim a trailing incomplete UTF-8 sequence. label[0..L-1] are the copied
    // bytes and label[L] holds the NUL (L = sizeof - 1). If the copy was cut in
    // the middle of a multi-byte character, the leftover lead/continuation bytes
    // would render as mojibake, so walk back to the final code point's lead byte
    // and drop the whole partial tail. This supersedes the old three-way
    // label[18]/[17]/[16] heuristic, whose first case became dead once label[18]
    // was forced to 0 and which missed a trailing 2-byte lead.
    const size_t L = sizeof(bookmark.label) - 1;
    size_t k = L;
    while (k > 0 && (static_cast<u8>(bookmark.label[k - 1]) & 0xC0) == 0x80)
        k--;                                   // skip trailing continuation bytes
    if (k > 0) {
        u8 lead = static_cast<u8>(bookmark.label[k - 1]);
        size_t need = 1;                       // total bytes this lead implies
        if      ((lead & 0xE0) == 0xC0) need = 2;
        else if ((lead & 0xF0) == 0xE0) need = 3;
        else if ((lead & 0xF8) == 0xF0) need = 4;
        if (L - (k - 1) < need) k--;           // incomplete -> also drop the lead
    }
    bookmark.label[k] = 0;
    bookmark.pointer.depth = 0;
    bookmark.deleted = false;
    bool success = false;
    u64 offset[MAX_POINTER_DEPTH + 1] = {0};
    u64 depth = 0;
    bool no7 = true;

    // num_opcodes is u32 (MaxOpcodes = 0x100). Using u8 here would wrap to 0
    // when num_opcodes == 256 and spin forever, and the in-body `i++`/`i+=2`
    // bumps can also overflow an u8. Use u32 to match the array capacity.
    for (u32 i = 0; i < cheat.num_opcodes; i++) {
        u8 opcode = (cheat.opcodes[i] >> 28) & 0xF;
        u8 FSA = (cheat.opcodes[i] >> 12) & 0xF;
        u8 T = (cheat.opcodes[i] >> 24) & 0xF;
        u8 M = (cheat.opcodes[i] >> 20) & 0xF;
        u8 A = cheat.opcodes[i] & 0xFF;

        if (depth > MAX_POINTER_DEPTH) {
            strncat(m_err_str, "CodeBiggerThanBookmarkErrorAddBookmarkCheatsLabelsStrText"_tr.c_str(), sizeof m_err_str -1);
            break;
        }

        if (opcode == 0) {
            i++;
            bookmark.offset = cheat.opcodes[i] + A * 0x100000000;
            switch (T) {
                case 1:
                    bookmark.type = SEARCH_TYPE_UNSIGNED_8BIT;
                    i++;
                    break;
                case 2:
                    bookmark.type = SEARCH_TYPE_UNSIGNED_16BIT;
                    i++;
                    break;
                case 4:
                    bookmark.type = SEARCH_TYPE_UNSIGNED_32BIT;
                    i++;
                    break;
                case 8:
                    bookmark.type = SEARCH_TYPE_UNSIGNED_64BIT;
                    i += 2;
                    break;
                default:
                    strncat(m_err_str, "CheatWrongWidthValueProcessErrorAddBookmarkCheatsLabelsStrText"_tr.c_str(), sizeof m_err_str -1);
                    bookmark.type = SEARCH_TYPE_UNSIGNED_32BIT;
                    i++;
                    break;
            };
            if (M != 0) {
                bookmark.heap = true;
            } else {
                bookmark.heap = false;
            }

            m_AttributeDumpBookmark->addData((u8 *)&bookmark, sizeof(bookmark_t));
            break;
        }
        if (depth == 0) {
            if (opcode == 5 && FSA == 0) {
                i++;
                if (M == 0)
                    offset[depth] = cheat.opcodes[i];
                else
                    offset[depth] = (m_debugger->queryMemory(metadata.heap_extents.base).type == 0) ? metadata.alias_extents.base : metadata.heap_extents.base - metadata.main_nso_extents.base + cheat.opcodes[i];
                depth++;
            }
            continue;
        }
        if (opcode == 5 && FSA == 1) {
            i++;
            offset[depth] = cheat.opcodes[i];
            depth++;
            continue;
        }
        if (opcode == 7 && FSA == 0) {
            i++;
            offset[depth] = cheat.opcodes[i];
            no7 = false;
            continue;
        }
        if (opcode == 6) {
            if (no7) {
                offset[depth] = 0;
            }
            switch (T) {
                case 1:
                    bookmark.type = SEARCH_TYPE_UNSIGNED_8BIT;
                    break;
                case 2:
                    bookmark.type = SEARCH_TYPE_UNSIGNED_16BIT;
                    break;
                case 4:
                    bookmark.type = SEARCH_TYPE_UNSIGNED_32BIT;
                    if ((i + 2 < cheat.num_opcodes) &&
                        (((cheat.opcodes[i + 2] & 0xF0000000) == 0x40000000) || ((cheat.opcodes[i + 2] & 0xF0000000) == 0x30000000) || ((cheat.opcodes[i + 2] & 0xF0000000) == 0xC0000000)))
                        bookmark.type = SEARCH_TYPE_FLOAT_32BIT;
                    break;
                case 8:
                    bookmark.type = SEARCH_TYPE_UNSIGNED_64BIT;
                    if ((i + 1 < cheat.num_opcodes) &&
                        (((cheat.opcodes[i + 1] & 0xF0000000) == 0x40000000) || ((cheat.opcodes[i + 1] & 0xF0000000) == 0x30000000) || ((cheat.opcodes[i + 1] & 0xF0000000) == 0xC0000000)))
                        bookmark.type = SEARCH_TYPE_FLOAT_64BIT;
                    break;
                default:
                    strncat(m_err_str, "CheatWrongWidthValueProcessErrorAddBookmarkCheatsLabelsStrText"_tr.c_str(), sizeof m_err_str -1);
                    bookmark.type = SEARCH_TYPE_UNSIGNED_32BIT;
                    break;
            }
            success = true;
            break;
        }
    }

    if (success) {
        bookmark.pointer.depth = depth;
        u64 nextaddress = metadata.main_nso_extents.base;
        u8 i = 0;
        for (int z = depth; z >= 0; z--) {
            bookmark.pointer.offset[z] = offset[i];
            nextaddress += bookmark.pointer.offset[z];
            MemoryInfo meminfo = m_debugger->queryMemory(nextaddress);
            if (meminfo.perm == Perm_Rw) {
                nextaddress = ReadPointerStep(m_debugger.get(), nextaddress);
            } else {
                success = false;
            }
            i++;
        }
    }
    if (success) {
        m_AttributeDumpBookmark->addData((u8 *)&bookmark, sizeof(bookmark_t));
        strncat(m_err_str, "AddPointerChainToBookmarkErrorAddBookmarkCheatsLabelsStrText"_tr.c_str(), sizeof m_err_str -1);
    } 
    else {
        if (bookmark.pointer.depth > 2)  // depth of 2 means only one pointer hit high chance of wrong positive
            m_AttributeDumpBookmark->addData((u8 *)&bookmark, sizeof(bookmark_t));
    }
    return true;
}

void getcheats() {
    m_displayed_cheat_lines = 0;
    char ss[200] = "";
    if (refresh_cheats) {
        m_cheats.reset();
        m_cheatCnt = 0;
        dmntchtGetCheatCount(&m_cheatCnt);
        bool need_apply_toggles = false;
        if (m_cheatCnt == 0) {
            // Fresh library (re)loaded into dmnt: all cheat indices restart, so any
            // remembered expansion would map onto the wrong sections.
            m_expanded_groups.clear();
            loadcheatsfromfile();
            dmntchtGetCheatCount(&m_cheatCnt);
            // Mark that we just freshly populated dmnt from the cheats .txt; the
            // persisted enabled/disabled state in toggles.brz has to be reapplied
            // once m_cheats is available (loadtoggles() looks cheats up by name
            // in the m_cheats cache).
            need_apply_toggles = true;
        }
        if (m_cheatCnt > 0) {
            m_cheats = std::make_unique<DmntCheatEntry[]>(m_cheatCnt);
            dmntchtGetCheats(m_cheats.get(), m_cheatCnt, 0, &m_cheatCnt);
            if (need_apply_toggles) {
                // Re-apply the persisted enabled/disabled state recorded in
                // toggles.brz. Without this call savetoggles() output is dead
                // data and every reload starts with all cheats unchecked.
                loadtoggles();
                // Refresh the local cache so the rendered checkboxes match dmnt.
                dmntchtGetCheats(m_cheats.get(), m_cheatCnt, 0, &m_cheatCnt);
            }
            // Recompute total_opcode here so that the A-button cap check in
            // handleInput() works correctly in outline mode too. The previous
            // location was below an early `return` when m_outline_mode==true,
            // which let users exceed MaximumProgramOpcodeCount and made the
            // dmnt side silently keep stale copies of cheats that the UI
            // could no longer disable.
            total_opcode = 0;
            for (u32 i = 0; i < m_cheatCnt; i++)
                if (m_cheats[i].enabled) total_opcode += m_cheats[i].definition.num_opcodes;
            // Refresh cheat_ids in m_toggle_list whenever the dmnt list has
            // been re-fetched. Add/Remove operations reassign ids, so without
            // this the key-combo shortcuts would silently toggle wrong cheats.
            ReconcileToggleList();
            // m_cheats was just re-read from dmnt, so .enabled reflects the
            // authoritative state (including the user's latest toggle). Persist
            // it so a future reload-from-file + loadtoggles() can't resurrect a
            // cheat the user unchecked. savetoggles() writes the whole list, so
            // one flag covers any number of toggles made this session.
            if (save_toggles_to_file) {
                savetoggles();
                save_toggles_to_file = false;
            }
        } else {
            CheatsLabelsStr[0] = 0;
            CheatsEnableStr[0] = 0;
            snprintf(CheatsEnableStr, sizeof CheatsEnableStr, "NoAvailableCheatsErrorGetCheatsCheatsEnableStrText"_tr.c_str());
            cheat_outline_entry_t outline_entry = {};
            m_cheat_outline.push_back(outline_entry);
            m_flat_row_count = 0;
            return;
        }
        refresh_cheats = false;
        // make outline
        if (m_outline_refresh) {
            m_outline_refresh = false;
            m_cheat_outline.clear();
            // Emit one collapsible group per --SectionStart/--SectionEnd (or
            // opcode 0x20000000/0x20000001) pair. The marker rows themselves are
            // never shown: the begin becomes the group header, the end is
            // consumed. A group's children are rendered only when it is expanded,
            // which is driven by the authoritative m_expanded_groups set (so a
            // rebuild after a toggle/delete reproduces the exact same view).
            auto pushGroup = [&](s32 begin, u32 endExclusive, bool collapsible) {
                bool expanded = !collapsible;              // malformed groups stay open
                if (collapsible) {
                    for (auto b : m_expanded_groups)
                        if (b == (u32)begin) { expanded = true; break; }
                }
                cheat_outline_entry_t h = {};
                h.index = (u32)begin;
                h.is_outline = true;
                h.always_expanded = !collapsible;
                h.expanded = expanded;
                h.size = endExclusive - (u32)begin - 1;
                h.title = SectionTitle(m_cheats[begin]);
                m_cheat_outline.push_back(h);
                if (expanded) {   // malformed, or a user-expanded group: inline contents
                    for (u32 k = (u32)begin + 1; k < endExclusive; k++)
                        if (!IsSectionBegin(m_cheats[k]) && !IsSectionEnd(m_cheats[k])) {
                            cheat_outline_entry_t e = {};
                            e.index = k;
                            e.is_outline = false;
                            m_cheat_outline.push_back(e);
                        }
                }
            };
            s32 open_begin = -1;
            for (u32 i = 0; i < m_cheatCnt; i++) {
                if (IsSectionBegin(m_cheats[i])) {
                    if (open_begin >= 0) pushGroup(open_begin, i, false);  // defensive
                    open_begin = (s32)i;
                } else if (IsSectionEnd(m_cheats[i])) {
                    if (open_begin >= 0) { pushGroup(open_begin, i, true); open_begin = -1; }
                } else if (open_begin < 0) {                                 // outside any group
                    cheat_outline_entry_t e = {};
                    e.index = i;
                    e.is_outline = false;
                    m_cheat_outline.push_back(e);
                }
                // inside a group (open_begin >= 0): content stays hidden for now
            }
            if (open_begin >= 0) pushGroup(open_begin, (u32)m_cheatCnt, false);  // trailing
        }
    }
    if (m_outline_mode && !m_show_only_enabled_cheats) { // take over and ignore the rest
        CheatsLabelsStr[0] = 0;
        CheatsCursor[0] = 0;
        CheatsEnableStr[0] = 0;
        snprintf(CheatsLabelsStr, sizeof CheatsLabelsStr, "\n");
        snprintf(CheatsEnableStr, sizeof CheatsEnableStr, "\n");
        // Section markers are bookkeeping rows, not cheats: they must not be
        // counted in the enabled/total tally, nor surface their own cheat id.
        u32 Enable_count = 0;
        u32 Real_count = 0;
        for (u32 i = 0; i < m_cheatCnt; i++) {
            if (IsSectionBegin(m_cheats[i]) || IsSectionEnd(m_cheats[i])) continue;
            Real_count++;
            if (m_cheats[i].enabled) Enable_count++;
        }
        // Resolve the highlighted row to a real cheat: a group header reports its
        // first child's ordinal instead of the marker, so moving onto a collapsed
        // label no longer reads as "one more cheat id".
        u32 oi = m_cheat_index + m_cheatlist_offset;
        if (oi >= m_cheat_outline.size()) oi = m_cheat_outline.empty() ? 0 : (u32)m_cheat_outline.size() - 1;
        u32 hl_index = m_cheat_outline[oi].index;
        if (m_cheat_outline[oi].is_outline) {
            u32 first = hl_index + 1;
            if (first < (u32)m_cheatCnt &&
                !IsSectionBegin(m_cheats[first]) && !IsSectionEnd(m_cheats[first]))
                hl_index = first;
        }
        // Show the id 1-based: RealCheatOrdinal is 0-based internally (it maps
        // to dmnt order), but users find "Cheat #1" for the first entry more
        // intuitive. -1 (an empty group header) falls back to 0.
        s32 display_id = RealCheatOrdinal(hl_index);
        display_id = (display_id >= 0) ? (display_id + 1) : 0;
        snprintf(CheatsCursor, sizeof CheatsCursor, "BasicInfoGetCheatsCheatsCursorText"_tr.c_str(), display_id, Enable_count, (long)Real_count);
        for (u8 line = 0; line < NUM_cheats; line++) {
            if ((line + m_cheatlist_offset) >= m_cheat_outline.size())
                break;
            {
                DmntCheatEntry cheat_entry = m_cheats[m_cheat_outline[line + m_cheatlist_offset].index];
                char namestr[100] = "";
                char toggle_str[100] = "";
                if (!m_show_only_enabled_cheats) {
                    for (size_t i = 0; i < m_toggle_list.size(); i++) {
                        // Match by stable readable_name when available; fall
                        // back to cheat_id comparison only for legacy entries
                        // that have no persisted name. NOTE: outline mode keeps
                        // a separate indirection (m_cheat_outline -> m_cheats),
                        // so we must look up the cheat through that mapping or
                        // the rendered combo label drifts off its row when an
                        // outline is collapsed.
                        const char *cur_name = cheat_entry.definition.readable_name;
                        bool same = (m_toggle_list[i].name[0] != 0)
                            ? (std::strncmp(m_toggle_list[i].name, cur_name, sizeof(m_toggle_list[i].name)) == 0)
                            : (m_toggle_list[i].cheat_id == cheat_entry.cheat_id);
                        if (same) {
                            bool match = false;
                            for (u32 j = 0; j < buttonCodes.size(); j++) {
                                if ((m_toggle_list[i].keycode & buttonCodes[j]) == (buttonCodes[j] & 0x0FFFFFFF)) {
                                    strcat(toggle_str, buttonNames[j].c_str());
                                    match = true;
                                }
                            }
                            if (match) strcat(toggle_str, ", ");
                        }
                    }
                }
                int buttoncode = cheat_entry.definition.opcodes[0];
                if ((buttoncode & 0xF0000000) == 0x80000000)
                    for (u32 i = 0; i < buttonCodes.size(); i++) {
                        if ((buttoncode & buttonCodes[i]) == buttonCodes[i])
                            strcat(namestr, buttonNames[i].c_str());
                    }
                if ((m_cheat_index == line) && (m_editCheat) && !m_cursor_on_bookmark) {
                    snprintf(ss, sizeof ss, "PressKeyForComboCountGetCheatsCheatsLabelsStrText"_tr.c_str(), keycount);
                    strcat(CheatsLabelsStr, ss);
                    snprintf(ss, sizeof ss, "\n");
                    strcat(CheatsEnableStr, ss);
                } else {
                    const cheat_outline_entry_t &oe = m_cheat_outline[line + m_cheatlist_offset];
                    if (oe.is_outline) {
                        // Section group header: show the extracted title in the
                        // name column and keep the checkbox column blank — the
                        // marker itself is not toggleable, so it must not render
                        // as a regular cheat row (this is what made the raw
                        // --SectionStart/--SectionEnd lines show up before).
                        std::string title = oe.title.empty()
                            ? std::string(cheat_entry.definition.readable_name) : oe.title;
                        const char *arrow = (oe.expanded || oe.always_expanded) ? "\u25BC" : "\u25B6";
                        snprintf(ss, sizeof ss, "%s %s (%d)\n", arrow, title.c_str(), (int)oe.size);
                        strcat(CheatsLabelsStr, ss);
                        snprintf(ss, sizeof ss, "\n");
                        strcat(CheatsEnableStr, ss);
                    } else {
                        snprintf(ss, sizeof ss, "%s%s %s\n", namestr, cheat_entry.definition.readable_name, toggle_str);
                        strcat(CheatsLabelsStr, ss);
                        if (m_show_only_enabled_cheats)
                            snprintf(ss, sizeof ss, "\n");
                        else
                            snprintf(ss, sizeof ss, "%s\n", (cheat_entry.enabled) ? "\u25A0" : "\u25A1");
                        strcat(CheatsEnableStr, ss);
                    }
                }
                snprintf(ss, sizeof ss, "%s\n", ((m_cheat_index == line) && (!m_show_only_enabled_cheats) && !m_cursor_on_bookmark) ? "\uE019" : "");
                strcat(CheatsCursor, ss);
                m_displayed_cheat_lines++;
            }
        }
        return;
    }
    // End make outline

    // Flat view (outline mode returned above). Build the screen-row -> raw index
    // map for this pass with a LOCAL cursor: skip section markers, and in the
    // enabled-only view skip disabled cheats. m_cheatlist_offset is the
    // persistent raw scroll base and is NEVER mutated here -- the previous design
    // bumped it to hide markers, but getcheats() runs every frame in this view, so
    // the skips accumulated, drifted the offset past m_cheatCnt and blanked the
    // whole list (both the show-all/X path and Y entered it, hence identical
    // symptoms). The renderer and actions read m_flat_row_raw / FlatSelectedRaw.
    {
        // Build the visible window; if the base lands past the last selectable
        // cheat (e.g. entering flat onto a trailing --SectionEnd marker after
        // a delete shrunk the array) the loop yields zero rows and the view
        // appears blank. Retry once from the top so the flat view is never
        // empty while real cheats exist.
        for (u32 attempt = 0; attempt < 2; attempt++) {
            u32 s = m_cheatlist_offset;
            m_flat_row_count = 0;
            for (u8 line = 0; line < NUM_cheats; line++) {
                while (s < (u32)m_cheatCnt && (IsSectionBegin(m_cheats[s]) || IsSectionEnd(m_cheats[s])))
                    s++;
                if (m_show_only_enabled_cheats)
                    while (s < (u32)m_cheatCnt && !m_cheats[s].enabled)
                        s++;
                if (s >= (u32)m_cheatCnt)
                    break;
                m_flat_row_raw[line] = s;
                m_flat_row_count = line + 1;
                s++;
            }
            if (m_flat_row_count > 0 || m_cheatlist_offset == 0) break;
            m_cheatlist_offset = 0;   // self-heal, retry from the top
        }
        m_real_cheat_count = 0;
        m_last_real_raw = 0;
        bool any_selectable = false;
        for (u32 i = 0; i < (u32)m_cheatCnt; i++) {
            if (IsSectionBegin(m_cheats[i]) || IsSectionEnd(m_cheats[i]))
                continue;
            m_real_cheat_count++;                                     // marker-free total (info line)
            if (m_show_only_enabled_cheats && !m_cheats[i].enabled)    // honor the view filter
                continue;
            m_last_real_raw = i;
            any_selectable = true;
        }
        if (!any_selectable)
            m_last_real_raw = 0;
        // Keep the highlighted row on a real, visible entry. Navigation can push
        // m_cheat_index past the (partial) last window; clamp it back so the cursor
        // never sits after the final cheat. This runs every frame in getcheats(),
        // so it self-corrects regardless of the update()/handleInput() order.
        if (m_cheat_index >= m_flat_row_count)
            m_cheat_index = (m_flat_row_count > 0) ? (m_flat_row_count - 1) : 0;
    }

    if (m_show_only_enabled_cheats) {
        if (m_displayed_cheat_lines > 0) {
        snprintf(CheatsEnableStr, sizeof CheatsEnableStr, "\n");
        snprintf(CheatsCursor, sizeof CheatsCursor, "\n");
        snprintf(CheatsLabelsStr, sizeof CheatsLabelsStr, "EnabledCheatsGetCheatsCheatsLabelsStrText"_tr.c_str(), m_displayed_cheat_lines);
        m_displayed_cheat_lines = 0;
        } else {
            CheatsLabelsStr[0] = 0;
            CheatsCursor[0] = 0;
            CheatsEnableStr[0] = 0;
        }
    } else {
        total_opcode = 0;
        for (u32 i = 0; i < m_cheatCnt; i++)
            if (m_cheats[i].enabled) total_opcode += m_cheats[i].definition.num_opcodes;
        // Report the highlighted real cheat 1-based (skipping markers) and the
        // marker-free total, matching the outline view's convention.
        u32 sel = FlatSelectedRaw();
        u32 sel_num = (sel == 0xFFFFFFFFu) ? 0 : m_cheats[sel].definition.num_opcodes;
        s32 disp_id = (sel == 0xFFFFFFFFu) ? 0 : (RealCheatOrdinal(sel) + 1);
        snprintf(CheatsCursor, sizeof CheatsCursor, "ShowTotalInfoGetCheatsCheatsCursorText"_tr.c_str(), disp_id, (long)m_real_cheat_count, sel_num, total_opcode, MaximumProgramOpcodeCount);
        snprintf(CheatsLabelsStr, sizeof CheatsLabelsStr, "\n");
        snprintf(CheatsEnableStr, sizeof CheatsEnableStr, "\n");
    }

    //  print some extra outline label
    if (!m_showALlCheats && !m_show_only_enabled_cheats) {
        for (auto entry : m_outline) {
            if (entry.index + m_cheats[0].cheat_id < m_outline[m_outline_index].index) {
                snprintf(ss, sizeof ss, "[%s]\n", entry.label.c_str());
                strcat(CheatsLabelsStr, "\n");
                strcat(CheatsCursor, "\n");
                strcat(CheatsEnableStr, ss);
            } else
                break;
        }
    }

    for (u8 line = 0; line < NUM_cheats; line++) {
        // Rows were resolved by the map above (section markers, and disabled
        // cheats in the enabled-only view, are already excluded there). Read
        // m_flat_row_raw[] directly and NEVER mutate m_cheatlist_offset.
        if (line >= m_flat_row_count)
            break;
        u32 ri = m_flat_row_raw[line];
        if (!m_showALlCheats && m_outline_index < (m_outline.size() - 1) && m_outline[m_outline_index + 1].index  < m_cheats[ri].cheat_id + 1 - m_cheats[0].cheat_id) break;
        {   
            char namestr[100] = "";
            char toggle_str[100] = "";
            if (!m_show_only_enabled_cheats) {
                for (size_t i = 0; i < m_toggle_list.size(); i++) {
                    // See note above in outline-mode renderer: prefer matching
                    // by readable_name so re-assigned cheat_ids don't break the
                    // on-screen key combo label.
                    const char *cur_name = m_cheats[ri].definition.readable_name;
                    bool same = (m_toggle_list[i].name[0] != 0)
                        ? (std::strncmp(m_toggle_list[i].name, cur_name, sizeof(m_toggle_list[i].name)) == 0)
                        : (m_toggle_list[i].cheat_id == m_cheats[ri].cheat_id);
                    if (same) {
                        bool match = false;
                        for (u32 j = 0; j < buttonCodes.size(); j++) {
                            if ((m_toggle_list[i].keycode & buttonCodes[j]) == (buttonCodes[j] & 0x0FFFFFFF)) {
                                strcat(toggle_str, buttonNames[j].c_str());
                                match = true;
                            };
                        };
                        if (match) strcat(toggle_str, ", ");
                    }
                }
            }
            int buttoncode = m_cheats[ri].definition.opcodes[0];
            if ((buttoncode & 0xF0000000) == 0x80000000)
                for (u32 i = 0; i < buttonCodes.size(); i++) {
                    if ((buttoncode & buttonCodes[i]) == buttonCodes[i])
                        strcat(namestr, buttonNames[i].c_str());
                }
            if ((m_cheat_index == line) && (m_editCheat) && !m_cursor_on_bookmark) {
                snprintf(ss, sizeof ss, "PressKeyForComboCountGetCheatsCheatsLabelsStrText"_tr.c_str(), keycount);
                strcat(CheatsLabelsStr, ss);
                snprintf(ss, sizeof ss, "\n");
                strcat(CheatsEnableStr, ss);
            } else {
                snprintf(ss, sizeof ss, "%s%s %s\n", namestr, m_cheats[ri].definition.readable_name, toggle_str);
                strcat(CheatsLabelsStr, ss);
                if (m_show_only_enabled_cheats)
                    snprintf(ss, sizeof ss, "\n");
                else
                    snprintf(ss, sizeof ss, "%s\n", (m_cheats[ri].enabled) ? "\u25A0" : "\u25A1");
                strcat(CheatsEnableStr, ss);
            }
            snprintf(ss, sizeof ss, "%s\n", ((m_cheat_index == line) && (!m_show_only_enabled_cheats) && !m_cursor_on_bookmark) ? "\uE019" : "");
            strcat(CheatsCursor, ss);
            m_displayed_cheat_lines++;
        }
    }
    //  print some extra outline label
    if (!m_showALlCheats && !m_show_only_enabled_cheats) {
        for (auto entry : m_outline) {
            if (entry.index + m_cheats[0].cheat_id <= m_cheats[m_cheat_index + m_cheatlist_offset].cheat_id)
                continue;
            else {
                snprintf(ss, sizeof ss, "[%s]\n", entry.label.c_str());
                strcat(CheatsLabelsStr, "\n");
                strcat(CheatsCursor, "\n");
                strcat(CheatsEnableStr, ss);
            }
        }
    }
}

class BookmarkOverlay : public tsl::Gui {
private:
	// Use the pre-parsed global masks (refreshed in ParseIniFile) rather than
	// re-running MapButtons() at every Gui construction.
	uint64_t bookmarkEnableCheatCombo = g_bookmarkEnableCheatCombo;
    uint64_t bookmarkPauseCheatCombo = g_bookmarkPauseCheatCombo;
    uint64_t bookmarkIncreaseFontSizeCombo = g_bookmarkIncreaseFontSizeCombo;
    uint64_t bookmarkDecreaseFontSizeCombo = g_bookmarkDecreaseFontSizeCombo;

public:
    BookmarkOverlay() {}

    virtual tsl::elm::Element *createUI() override {
        std::memset(BookmarkLabels, 0, sizeof(BookmarkLabels));
        std::memset(Variables, 0, sizeof(Variables));
        std::memset(CheatsLabelsStr, 0, sizeof(CheatsLabelsStr));
        std::memset(Cursor, 0, sizeof(Cursor));
        std::memset(MultiplierStr, 0, sizeof(MultiplierStr));
        auto rootFrame = new tsl::elm::OverlayFrame("", "");
        auto Status = new tsl::elm::CustomDrawer([](tsl::gfx::Renderer *renderer, u16 x, u16 y, u16 w, u16 h) {
            std::pair<s32, s32> extent1;
            renderer->m_maxY = 0;
            extent1 = renderer->drawString(Title_str.c_str(), false, 5, fontsize +5 , fontsize, renderer->a(0xFFFF));
            renderer->m_maxX = 0;
            renderer->drawString(BookmarkLabels, false, 5, extent1.second + fontsize + 5, fontsize, renderer->a(0xFFFF));
            renderer->drawString(Variables, false, renderer->m_maxX + 5, extent1.second + fontsize + 5, fontsize, renderer->a(0xFFFF));
            renderer->drawString(MultiplierStr, false, renderer->m_maxX + 5, extent1.second + fontsize + 5, fontsize, renderer->a(0xFFFF));
            renderer->drawString(CheatsLabelsStr, false, 5, renderer->m_maxY, fontsize, renderer->a(0xFFFF));
            renderer->drawRect(0, 0, std::max(renderer->m_maxX, extent1.first + 5) + 5, renderer->m_maxY + 5 - fontsize, a(0x7111));
        });
        rootFrame->setContent(Status);

        return rootFrame;
    }

    virtual void update() override {
        if (!dmnt_present || !m_debugger)
            return;

        if (m_on_show) {
            tsl::hlp::requestForeground(false);
            m_on_show = false;
        }
        dmntchtHasCheatProcess(&(m_debugger->m_dmnt));
        if (!m_debugger->m_dmnt) {
            tsl::goBack();
        }
        BookmarkLabels[0] = 0;
        Variables[0] = 0;
        Cursor[0] = 0;
        MultiplierStr[0] = 0;
        Title_str = "UpdateStatusTitleStrBookmarkOverlayCustomDrawerText"_tr;
        m_displayed_bookmark_lines = 0;
        for (u8 line = 0; line < NUM_bookmark; line++) {
            if ((line + m_addresslist_offset) >= (m_AttributeDumpBookmark->size() / sizeof(bookmark_t)))
                break;
            char ss[200] = "";
            bookmark_t bookmark;
            {
                u64 address = 0;
                m_AttributeDumpBookmark->getData((line + m_addresslist_offset) * sizeof(bookmark_t), &bookmark, sizeof(bookmark_t));
                if (bookmark.magic!=0x1289) bookmark.multiplier = 1;
                if (bookmark.pointer.depth > 0)  // check if pointer chain point to valid address update address if necessary
                {
                    u64 nextaddress = metadata.main_nso_extents.base;
                    for (int z = bookmark.pointer.depth; z >= 0; z--) {
                        nextaddress += bookmark.pointer.offset[z];
                        MemoryInfo meminfo = m_debugger->queryMemory(nextaddress);
                        if (meminfo.perm == Perm_Rw)
                            if (z == 0) {
                                if (address == nextaddress) {
                                } else {
                                    address = nextaddress;
                                }
                            } else
                                nextaddress = ReadPointerStep(m_debugger.get(), nextaddress);
                        else {
                            break;
                        }
                    }
                } else {
                    address = ((bookmark.heap) ? ((m_debugger->queryMemory(metadata.heap_extents.base).type == 0) ? metadata.alias_extents.base : metadata.heap_extents.base) : metadata.main_nso_extents.base) + bookmark.offset;
                }
                searchValue_t value = {0};
                m_debugger->readMemory(&value, DataTypeSize(bookmark.type), address);
                if ((m_oldvalue[line]._u64 == 0) || (m_oldvalue[line]._s64 > value._s64))
                    m_oldvalue[line]._s64 = value._s64;
                else if (bookmark.multiplier != 1) {
                    switch (bookmark.type) {
                        case SEARCH_TYPE_FLOAT_32BIT:
                            if (m_oldvalue[line]._f32 < value._f32) {
                                m_oldvalue[line]._f32 = (value._f32 - m_oldvalue[line]._f32) * bookmark.multiplier + m_oldvalue[line]._f32;
                            };
                            break;
                        case SEARCH_TYPE_FLOAT_64BIT:
                            if (m_oldvalue[line]._f64 < value._f64) {
                                m_oldvalue[line]._f64 = (value._f64 - m_oldvalue[line]._f64) * bookmark.multiplier + m_oldvalue[line]._f64;
                            };
                            break;
                        case SEARCH_TYPE_UNSIGNED_8BIT:
                        case SEARCH_TYPE_UNSIGNED_16BIT:
                        case SEARCH_TYPE_UNSIGNED_32BIT:
                        case SEARCH_TYPE_UNSIGNED_64BIT:
                            if (m_oldvalue[line]._u64 < value._u64) {
                                m_oldvalue[line]._u64 = (value._u64 - m_oldvalue[line]._u64) * bookmark.multiplier + m_oldvalue[line]._u64;
                            };
                            break;
                        default:
                            if (m_oldvalue[line]._s64 < value._s64) {
                                m_oldvalue[line]._s64 = (value._s64 - m_oldvalue[line]._s64) * bookmark.multiplier + m_oldvalue[line]._s64;
                            };
                            break;
                    };
                    m_debugger->writeMemory(&(m_oldvalue[line]), DataTypeSize(bookmark.type), address);
                }
                snprintf(ss, sizeof ss, "%s\n", _getAddressDisplayString(address, m_debugger.get(), (searchType_t)bookmark.type).c_str());
                strcat(Variables, ss);
                snprintf(ss, sizeof ss, "%s\n", bookmark.label);
                strcat(BookmarkLabels, ss);
                snprintf(ss, sizeof ss, "\n");
                strcat(Cursor, ss);
                snprintf(ss, sizeof ss, (bookmark.multiplier != 1) ? "X%02d\n" : "\n", bookmark.multiplier);
                strcat(MultiplierStr, ss);
                m_displayed_bookmark_lines++;
            }
        }
        m_show_only_enabled_cheats = true;
        m_cheatlist_offset = 0;
        getcheats();
    }

    virtual bool handleInput(u64 keysDown, u64 keysHeld, const HidTouchState &touchPos, HidAnalogStickState leftJoyStick, HidAnalogStickState rightJoyStick) override {
        if (keysDown & HidNpadButton_B) {
            return true;
        }

        for (const auto &entry : m_toggle_list) {
            if (((keysHeld | keysDown) == entry.keycode) && (keysDown & entry.keycode)) {
                // Resolve the live cheat_id by stable name first. Cached
                // entry.cheat_id can be stale after Add/Remove cycles, which
                // previously caused key combos to silently toggle a different
                // cheat (and look like "disable doesn't work").
                u32 live_id = 0;
                bool ambiguous = false;
                if (LookupCheatIdByName(entry.name, &live_id, &ambiguous)) {
                    dmntchtToggleCheat(ambiguous ? entry.cheat_id : live_id);
                    save_toggles_to_file = true;
                    refresh_cheats = true;
                } else if (entry.name[0] == 0) {
                    // Legacy entry without a persisted name: fall back to the
                    // id we loaded from .bz1.
                    dmntchtToggleCheat(entry.cheat_id);
                    save_toggles_to_file = true;
                    refresh_cheats = true;
                }
            }
        }
        if (isKeyComboJustPressed(keysHeld, keysDown, bookmarkEnableCheatCombo)) {
            m_cheatlist_offset = m_cheatlist_offset_save;
            TeslaFPS = 50;
            IsFrameBackground = false;
            tsl::hlp::requestForeground(true);
            FullMode = false;
            deactivateOriginalFooter = true;
            tsl::goBack();
            return true;
        }
        if (isKeyComboJustPressed(keysHeld, keysDown, bookmarkPauseCheatCombo)) {
            m_cheatlist_offset = m_cheatlist_offset_save;
            TeslaFPS = 50;
            IsFrameBackground = false;
            tsl::hlp::requestForeground(true);
            FullMode = false;
            deactivateOriginalFooter = true;
            dmntchtPauseCheatProcess();
            tsl::goBack();
            return true;
        }
        if (isKeyComboJustPressed(keysHeld, keysDown, bookmarkIncreaseFontSizeCombo)) {
            fontsize++;
            return true;
        }
        if (isKeyComboJustPressed(keysHeld, keysDown, bookmarkDecreaseFontSizeCombo)) {
            fontsize--;
            return true;
        }
        return false;
    }
};

//Main Menu
class MainMenu : public tsl::Gui {
private:
	// Pre-parsed global masks (refreshed in ParseIniFile); avoids re-running
	// MapButtons() on every Gui construction.
	uint64_t mainMenuChangeToBookmarkCombo = g_mainMenuChangeToBookmarkCombo;
    uint64_t mainMenuIncreaseFontSizeCombo = g_mainMenuIncreaseFontSizeCombo;
    uint64_t mainMenuDecreaseFontSizeCombo = g_mainMenuDecreaseFontSizeCombo;
    uint64_t mainMenuOutlineModeSwitchesCombo = g_mainMenuOutlineModeSwitchesCombo;
    uint64_t mainMenuSetBookmarkMultipier = g_mainMenuSetBookmarkMultipier;
    uint64_t mainMenuNextLabel = g_mainMenuNextLabel;
    uint64_t mainMenuPreviousLabel = g_mainMenuPreviousLabel;
public:
    MainMenu() {}
    ~MainMenu() {
        refresh_cheats = false;
        if (m_cheats) {
            m_cheats.reset();
            m_cheatCnt = 0;
        }
    }

    virtual tsl::elm::Element *createUI() override {
        tsl::elm::OverlayFrame *rootFrame = nullptr;
        if (dmnt_present && m_debugger) {
            dmntchtHasCheatProcess(&(m_debugger->m_dmnt));
            if (m_debugger->m_dmnt) {
                TeslaFPS = 50;
                IsFrameBackground = false;
                tsl::hlp::requestForeground(true);
                FullMode = false;
                deactivateOriginalFooter = true;
                m_on_show = true;
                refresh_cheats = true;
                m_cheatlist_offset = m_cheatlist_offset_save;
                if (m_outline.size() <= 1) m_showALlCheats = true;
                rootFrame = new tsl::elm::OverlayFrame("", "");
                auto Status = new tsl::elm::CustomDrawer([](tsl::gfx::Renderer *renderer, u16 x, u16 y, u16 w, u16 h) {
                    renderer->drawRect(0, 0, tsl::cfg::FramebufferWidth , tsl::cfg::FramebufferHeight, a(0x7111));
                    renderer->m_maxY = 0;
                    renderer->drawString(BookmarkLabels, false, 65, fontsize, fontsize, renderer->a(0xFFFF));
                    renderer->drawString(Variables, false, 210, fontsize, fontsize, renderer->a(0xFFFF));
                    renderer->drawString(Cursor, false, 5, fontsize, fontsize, renderer->a(0xFFFF));
                    renderer->drawString(MultiplierStr, false, 25, fontsize, fontsize, renderer->a(0xFFFF));
                    m_NUM_cheats = std::min(m_displayed_cheat_lines + (s32)(tsl::cfg::FramebufferHeight - renderer->m_maxY) / (fontsize + 3), (u32)MAX_NUM_cheats);
                });
                rootFrame->setContent(Status);
            } else {
                if (TeslaFPS != 60) {
                    FullMode = true;
                    tsl::hlp::requestForeground(true);
                    TeslaFPS = 60;
                    deactivateOriginalFooter = false;
                    IsFrameBackground = true;
                }
                rootFrame = new tsl::elm::OverlayFrame("PluginName"_tr, VERSION);
                auto list = new tsl::elm::List();
                auto NoGame = new tsl::elm::ListItem("GameNotRunningMainMenuListItemText"_tr);
                list->addItem(NoGame);
                rootFrame->setContent(list);
            }
        } else {
            if (TeslaFPS != 60) {
                FullMode = true;
                tsl::hlp::requestForeground(true);
                TeslaFPS = 60;
                deactivateOriginalFooter = false;
                IsFrameBackground = true;
            }
            rootFrame = new tsl::elm::OverlayFrame("PluginName"_tr, VERSION);
            auto list = new tsl::elm::List();
            // dmnt_present tells the two "not working" cases apart: service absent
            // (dmnt_present false) vs service running but no live cheat process/game
            // (m_debugger was reset in init_se_tools). Show the accurate message.
            if (dmnt_present)
                list->addItem(new tsl::elm::ListItem("GameNotRunningMainMenuListItemText"_tr));
            else
                list->addItem(new tsl::elm::ListItem("NoDmntMainMenuListItemText"_tr));
            rootFrame->setContent(list);
        }

        return rootFrame;
    }

    virtual void update() override {
        if (!dmnt_present || !m_debugger)
            return;

        dmntchtHasCheatProcess(&(m_debugger->m_dmnt));
        if (!m_debugger->m_dmnt)
            return;

        if (m_edit_value) {
            // Bookmark value editing is a modal text editor: the list footer
            // keys (notably "B Exit") are wrong here — B is backspace and X
            // cancels/leaves editing. Build a neutral title/PID-only header that
            // still occupies the same 5-line block reserved by BookmarkLabels /
            // Variables / MultiplierStr (so row alignment holds), and let the
            // edit footer appended further down describe the real keys.
            snprintf(Cursor, sizeof Cursor, "UpdateEditValueHeaderMainMenuCustomDrawerText"_tr.c_str(),
                    m_titleName.c_str(), m_versionString.c_str(), metadata.process_id, metadata.title_id, build_id[0], build_id[1], build_id[2], build_id[3], build_id[4], build_id[5], build_id[6], build_id[7]);
        } else if (m_cheatCnt == 0) {
            snprintf(Cursor, sizeof Cursor, "UpdateCursorNoCheatsMainMenuCustomDrawerText"_tr.c_str(),
                    m_titleName.c_str(), m_versionString.c_str(), metadata.process_id, metadata.title_id, build_id[0], build_id[1], build_id[2], build_id[3], build_id[4], build_id[5], build_id[6], build_id[7]);
        } else if (m_cursor_on_bookmark) {
            snprintf(Cursor, sizeof Cursor, "UpdateCursorOnBookmarkMainMenuCustomDrawerText"_tr.c_str(),
                    m_titleName.c_str(), m_versionString.c_str(), metadata.process_id, metadata.title_id, build_id[0], build_id[1], build_id[2], build_id[3], build_id[4], build_id[5], build_id[6], build_id[7]);
        } else {
            snprintf(Cursor, sizeof Cursor, "UpdateCursorNotOnBookmarkMainMenuCustomDrawerText"_tr.c_str(),
                    m_titleName.c_str(), m_versionString.c_str(), metadata.process_id, metadata.title_id, build_id[0], build_id[1], build_id[2], build_id[3], build_id[4], build_id[5], build_id[6], build_id[7]);
        }
        // Please note, the number of '\n' of all labels for displaying, must be the same
        snprintf(BookmarkLabels, sizeof BookmarkLabels, "\n\n\n\n\n");
        snprintf(Variables, sizeof Variables, "\n\n\n\n\n");
        snprintf(MultiplierStr, sizeof MultiplierStr, "\n\n\n\n\n");
        for (u8 line = 0; line < NUM_bookmark; line++) {
            if ((line + m_addresslist_offset) >= (m_AttributeDumpBookmark->size() / sizeof(bookmark_t)))
                break;
            char ss[200] = "";
            bookmark_t bookmark;
            {
                u64 address = 0;
                m_AttributeDumpBookmark->getData((line + m_addresslist_offset) * sizeof(bookmark_t), &bookmark, sizeof(bookmark_t));
                if (bookmark.magic!=0x1289) bookmark.multiplier = 1;
                if (bookmark.pointer.depth > 0)  // check if pointer chain point to valid address update address if necessary
                {
                    u64 nextaddress = metadata.main_nso_extents.base;
                    for (int z = bookmark.pointer.depth; z >= 0; z--) {
                        nextaddress += bookmark.pointer.offset[z];
                        MemoryInfo meminfo = m_debugger->queryMemory(nextaddress);
                        if (meminfo.perm == Perm_Rw)
                            if (z == 0) {
                                if (address == nextaddress) {
                                } else {
                                    address = nextaddress;
                                }
                            } else
                                nextaddress = ReadPointerStep(m_debugger.get(), nextaddress);
                        else {
                            break;
                        }
                    }
                } else {
                    address = ((bookmark.heap) ? ((m_debugger->queryMemory(metadata.heap_extents.base).type == 0) ? metadata.alias_extents.base : metadata.heap_extents.base) : metadata.main_nso_extents.base) + bookmark.offset;
                }
                searchValue_t value = {0};
                m_debugger->readMemory(&value, DataTypeSize(bookmark.type), address);
                if ((m_oldvalue[line]._u64 == 0) || (m_oldvalue[line]._s64 > value._s64))
                    m_oldvalue[line]._s64 = value._s64;
                else if (bookmark.multiplier != 1) {
                    switch (bookmark.type) {
                        case SEARCH_TYPE_FLOAT_32BIT:
                            if (m_oldvalue[line]._f32 < value._f32) {
                                m_oldvalue[line]._f32 = (value._f32 - m_oldvalue[line]._f32) * bookmark.multiplier + m_oldvalue[line]._f32;
                            };
                            break;
                        case SEARCH_TYPE_FLOAT_64BIT:
                            if (m_oldvalue[line]._f64 < value._f64) {
                                m_oldvalue[line]._f64 = (value._f64 - m_oldvalue[line]._f64) * bookmark.multiplier + m_oldvalue[line]._f64;
                            };
                            break;
                        case SEARCH_TYPE_UNSIGNED_8BIT:
                        case SEARCH_TYPE_UNSIGNED_16BIT:
                        case SEARCH_TYPE_UNSIGNED_32BIT:
                        case SEARCH_TYPE_UNSIGNED_64BIT:
                            if (m_oldvalue[line]._u64 < value._u64) {
                                m_oldvalue[line]._u64 = (value._u64 - m_oldvalue[line]._u64) * bookmark.multiplier + m_oldvalue[line]._u64;
                            };
                            break;
                        default:
                            if (m_oldvalue[line]._s64 < value._s64) {
                                m_oldvalue[line]._s64 = (value._s64 - m_oldvalue[line]._s64) * bookmark.multiplier + m_oldvalue[line]._s64;
                            };
                            break;
                    };
                    m_debugger->writeMemory(&(m_oldvalue[line]), DataTypeSize(bookmark.type), address);
                }
                snprintf(ss, sizeof ss, "%s\n", ((m_index == line) && m_edit_value) ? valueStr_edit_display(Display).c_str() : _getAddressDisplayString(address, m_debugger.get(), (searchType_t)bookmark.type).c_str());
                if (m_index == line) {
                    m_selected_address = address;
                    m_selected_type = bookmark.type;
                }
                if ((m_index == line) && (m_editCheat) && m_cursor_on_bookmark) {
                    strcat(Variables, "\n");
                    snprintf(ss, sizeof ss, "UpdateBookmarkPressKeyForComboCountMainMenuCustomDrawerText"_tr.c_str(), keycount);
                } else {
                    char toggle_str[100] = "";
                    for (auto entry : m_breeze_action_list) {
                        if (entry.index == line) {
                            for (u32 j = 0; j < buttonCodes.size(); j++) {
                                if ((entry.keycode & buttonCodes[j]) == (buttonCodes[j] & 0x0FFFFFFF)) {
                                    strcat(toggle_str, buttonNames[j].c_str());
                                };
                            };
                            strcat(toggle_str, ", ");
                        }
                    }
                    if (strlen(toggle_str) != 0) {
                        strcat(Variables, "\n");
                        snprintf(ss, sizeof ss, "%s %s\n", bookmark.label, toggle_str);
                    } else {
                        strcat(Variables, ss);
                        snprintf(ss, sizeof ss, "%s\n", bookmark.label);
                    }
                }
                strcat(BookmarkLabels, ss);
                snprintf(ss, sizeof ss, "%s\n", ((m_index == line) && m_cursor_on_bookmark) ? "\uE019" : "");
                strcat(Cursor, ss);
                snprintf(ss, sizeof ss, "X%02d\n", bookmark.multiplier);
                strcat(MultiplierStr, ss);
            }
        }
        if (m_edit_value) {
            SafeCat(Cursor, sizeof Cursor, ("UpdateEditCheatValueMainMenuCustomDrawerText"_tr).c_str());
            SafeCat(MultiplierStr, sizeof MultiplierStr, "\n");
            for (u8 i = 0; i < keyNames.size(); i++) {
                SafeCat(Cursor, sizeof Cursor, (i == m_value_edit_index) ? "->\n" : "\n");
                SafeCat(MultiplierStr, sizeof MultiplierStr, (keyNames[i]+"\n").c_str());
            }
            return;
        }
        if (m_show_outline) {
            SafeCat(Cursor, sizeof Cursor, ("UpdateShowOutlineCursorMainMenuCustomDrawerText"_tr).c_str());
            SafeCat(BookmarkLabels, sizeof BookmarkLabels, "\n");
            SafeCat(MultiplierStr, sizeof MultiplierStr, "\n");
            for (u8 i = 0; i < m_outline.size(); i++) {
                SafeCat(Cursor, sizeof Cursor, (i == m_outline_index && !m_cursor_on_bookmark) ? "\uE019\n" : "\n");
                SafeCat(MultiplierStr, sizeof MultiplierStr, ("[" + m_outline[i].label + "]\n").c_str());
            }
            return;
        }
        if (m_AttributeDumpBookmark->size() == 0) m_cursor_on_bookmark = false;
        m_show_only_enabled_cheats = false;
        getcheats();
        // Append the cheat columns onto the (already header+bookmark-filled)
        // shared buffers using remaining capacity, never sizeof-1.
        SafeCat(BookmarkLabels, sizeof BookmarkLabels, CheatsLabelsStr);
        SafeCat(Cursor, sizeof Cursor, CheatsCursor);
        SafeCat(MultiplierStr, sizeof MultiplierStr, CheatsEnableStr);
    }

    virtual bool handleInput(u64 keysDown, u64 keysHeld, const HidTouchState &touchPos, HidAnalogStickState leftJoyStick, HidAnalogStickState rightJoyStick) override {
        if (!dmnt_present || !m_debugger) {
            if (keysDown & HidNpadButton_B) {
                tsl::goBack();
            }
            return true;
        }

        dmntchtHasCheatProcess(&(m_debugger->m_dmnt));
        // Bookmark value editing is modal: while engaged, none of the guards
        // below may hijack input. They call tsl::goBack() on B, and because
        // MainMenu is the root Gui that hides/closes the whole overlay — which
        // is exactly why pressing B during editing quit the overlay (instead of
        // deleting a character) whenever the cheat process momentarily reported
        // absent or the cheat count dropped to 0. Gate them on !m_edit_value so
        // execution always reaches the m_edit_value handler further down.
        if (!m_edit_value && !m_debugger->m_dmnt) {
            if (keysDown & HidNpadButton_B) {
                tsl::goBack();
            }
            return true;
        }

		if (!m_edit_value && !m_cheatCnt) {
            if (keysDown & HidNpadButton_B) {
                tsl::goBack();
            }
            return true;
        }

        static u32 keycode;
        u32 redirect_index = m_cheat_index + m_cheatlist_offset;
        if (!m_edit_value && m_outline_mode) {
            // m_cheat_outline is rebuilt on refresh and can be shorter than
            // the raw cheat count (collapsed groups). Clamp before indexing;
            // if there is nothing to point at, ignore this input frame.
            if (m_cheat_outline.empty()) return true;
            if (redirect_index >= m_cheat_outline.size())
                redirect_index = (u32)m_cheat_outline.size() - 1;
            redirect_index = m_cheat_outline[redirect_index].index;
        } else if (!m_edit_value) {
            // Non-outline flat view: redirect_index must be the raw index of the
            // highlighted REAL cheat. m_flat_row_raw[] already excludes section
            // markers, so resolve through it rather than treating
            // m_cheat_index + m_cheatlist_offset as a raw m_cheats offset (which
            // drifts onto a marker or the wrong cheat once rows are hidden).
            u32 r = FlatSelectedRaw();
            if (r == 0xFFFFFFFFu)
                return true;
            redirect_index = r;
        }
        for (const auto &entry : m_toggle_list) {
            if (((keysHeld | keysDown) == entry.keycode) && (keysDown & entry.keycode)) {
                // Same live-id resolution as BookmarkOverlay: cheat_id from the
                // .bz1 file or even from a previous refresh can be stale after
                // edits that re-add cheats.
                u32 live_id = 0;
                bool ambiguous = false;
                if (LookupCheatIdByName(entry.name, &live_id, &ambiguous)) {
                    dmntchtToggleCheat(ambiguous ? entry.cheat_id : live_id);
                    save_toggles_to_file = true;
                    refresh_cheats = true;
                } else if (entry.name[0] == 0) {
                    dmntchtToggleCheat(entry.cheat_id);
                    save_toggles_to_file = true;
                    refresh_cheats = true;
                }
            }
        }
        if (m_editCheat) {
            if (keysDown == 0) return false;
            keycode = keycode | keysDown;  // Waitforkey_menu will send keycode in index to this buttonid;
            keycount--;
            if (keycount > 0) return true;
            m_editCheat = false;
            if (m_get_toggle_keycode) {
                toggle_list_t entry = {};
                entry.cheat_id = m_cheats[redirect_index].cheat_id;
                entry.keycode = keycode;
                // Persist the stable name alongside the (volatile) cheat_id so
                // that subsequent AddCheat/RemoveCheat cycles don't strand this
                // entry on a wrong cheat.
                std::memcpy(entry.name, m_cheats[redirect_index].definition.readable_name, sizeof(entry.name));
                entry.name[sizeof(entry.name) - 1] = 0;
                m_toggle_list.push_back(entry);
                // New user-assigned toggle combo: mark the .bz1 dirty so the
                // self-describing header + persisted name actually reach disk on
                // exit. Without this the save path never ran and load fell back to
                // the legacy 8-byte reader, dropping name/stride.
                save_breeze_toggle_to_file = true;
                m_get_toggle_keycode = false;
            } else if (m_get_action_keycode) {
                breeze_action_list_t entry;
                entry.index = m_index;
                entry.keycode = keycode;
                entry.breeze_action = Set;
                entry.freeze_value._u16 = 10;
                m_breeze_action_list.push_back(entry); // temp test code
                save_breeze_action_to_file = true;     // persist the .bz2 on exit
                m_get_action_keycode = false;
            } else {
                if ((m_cheats[redirect_index].definition.opcodes[0] & 0xF0000000) == 0x80000000) {
                    m_cheats[redirect_index].definition.opcodes[0] = keycode;
                } else {
                    // opcodes[] is a fixed uint32_t[0x100] (DmntCheatDefinition).
                    // This branch prepends two words (a key-combo word + a
                    // 0x20000000 separator, shifting the existing ones up), so it
                    // needs room for num_opcodes + 2 within the real array.
                    // MaximumProgramOpcodeCount (0x400) is the dmnt IPC budget,
                    // NOT the array size; the old bound `num_opcodes < 0x100 + 2`
                    // let num_opcodes reach 0x101, so opcodes[num_opcodes + 1] and
                    // the shift loop wrote past opcodes[0x100] and corrupted the
                    // neighbouring DmntCheatEntry in the m_cheats heap array.
                    constexpr u32 opcodeCap =
                        static_cast<u32>(sizeof(m_cheats[redirect_index].definition.opcodes) /
                                         sizeof(m_cheats[redirect_index].definition.opcodes[0]));
                    if (m_cheats[redirect_index].definition.num_opcodes + 2 <= opcodeCap) {
                        m_cheats[redirect_index].definition.opcodes[m_cheats[redirect_index].definition.num_opcodes + 1] = 0x20000000;

                        for (u32 i = m_cheats[redirect_index].definition.num_opcodes; i > 0; i--) {
                            m_cheats[redirect_index].definition.opcodes[i] = m_cheats[redirect_index].definition.opcodes[i - 1];
                        }
                        m_cheats[redirect_index].definition.num_opcodes += 2;
                        m_cheats[redirect_index].definition.opcodes[0] = keycode;
                    }
                }
                dmntchtRemoveCheat(m_cheats[redirect_index].cheat_id);
                u32 outid = 0;
                dmntchtAddCheat(&(m_cheats[redirect_index].definition), m_cheats[redirect_index].enabled, &outid);
                refresh_cheats = true;
            };
            return true;
        }
        if (m_edit_value) {
            if (keysDown & HidNpadButton_L) {
                if (value_pos > 0) value_pos--;
                return true;
            }
            if (keysDown & HidNpadButton_R) {
                if (value_pos < valueStr.length()) value_pos++;
                return true;
            }
            if (keysDown & HidNpadButton_A) {
                valueStr_edit_display(Insert);
                value_pos++;
                return true;
            }
            if (keysDown & HidNpadButton_Plus) {
                searchValue_t searchValue = {0};
                if (m_hex_mode == false)
                    switch (m_selected_type) {
                        case SEARCH_TYPE_FLOAT_32BIT:
                            searchValue._f32 = static_cast<float>(std::atof(valueStr.c_str()));
                            break;
                        case SEARCH_TYPE_FLOAT_64BIT:
                            searchValue._f64 = std::atof(valueStr.c_str());
                            break;
                        case SEARCH_TYPE_UNSIGNED_8BIT:
                            searchValue._u8 = std::atol(valueStr.c_str());
                            break;
                        case SEARCH_TYPE_SIGNED_8BIT:
                            searchValue._s8 = std::atol(valueStr.c_str());
                            break;
                        case SEARCH_TYPE_UNSIGNED_16BIT:
                            searchValue._u16 = std::atol(valueStr.c_str());
                            break;
                        case SEARCH_TYPE_SIGNED_16BIT:
                            searchValue._s16 = std::atol(valueStr.c_str());
                            break;
                        case SEARCH_TYPE_UNSIGNED_32BIT:
                            searchValue._u32 = std::atol(valueStr.c_str());
                            break;
                        case SEARCH_TYPE_SIGNED_32BIT:
                            searchValue._s32 = std::atol(valueStr.c_str());
                            break;
                        case SEARCH_TYPE_UNSIGNED_64BIT:
                            searchValue._u64 = std::atol(valueStr.c_str());
                            break;
                        case SEARCH_TYPE_SIGNED_64BIT:
                            searchValue._s64 = std::atol(valueStr.c_str());
                            break;
                        default:
                            searchValue._u64 = std::atol(valueStr.c_str());
                            break;
                    }
                else
                    switch (m_selected_type) {
                        case SEARCH_TYPE_FLOAT_32BIT:
                            searchValue._f32 = static_cast<float>(std::atof(valueStr.c_str()));
                            break;
                        case SEARCH_TYPE_FLOAT_64BIT:
                            searchValue._f64 = std::atof(valueStr.c_str());
                            break;
                        case SEARCH_TYPE_UNSIGNED_8BIT:
                            searchValue._u8 = std::strtoul(valueStr.c_str(), NULL, 16);
                            break;
                        case SEARCH_TYPE_SIGNED_8BIT:
                            searchValue._s8 = std::strtoul(valueStr.c_str(), NULL, 16);
                            break;
                        case SEARCH_TYPE_UNSIGNED_16BIT:
                            searchValue._u16 = std::strtoul(valueStr.c_str(), NULL, 16);
                            break;
                        case SEARCH_TYPE_SIGNED_16BIT:
                            searchValue._s16 = std::strtoul(valueStr.c_str(), NULL, 16);
                            break;
                        case SEARCH_TYPE_UNSIGNED_32BIT:
                            searchValue._u32 = std::strtoul(valueStr.c_str(), NULL, 16);
                            break;
                        case SEARCH_TYPE_SIGNED_32BIT:
                            searchValue._s32 = std::strtoul(valueStr.c_str(), NULL, 16);
                            break;
                        case SEARCH_TYPE_UNSIGNED_64BIT:
                            searchValue._u64 = std::strtoul(valueStr.c_str(), NULL, 16);
                            break;
                        case SEARCH_TYPE_SIGNED_64BIT:
                            searchValue._s64 = std::strtoul(valueStr.c_str(), NULL, 16);
                            break;
                        default:
                            searchValue._u64 = std::strtoul(valueStr.c_str(), NULL, 16);
                            break;
                    }
                m_debugger->writeMemory(&searchValue, DataTypeSize(m_selected_type), m_selected_address);
                m_edit_value = false;
                return true;
            }
            if (keysDown & HidNpadButton_B) {
                if (value_pos > 0) {
                    valueStr_edit_display(Delete);
                    value_pos--;
                }
                return true;
            }
            if ((keysDown & HidNpadButton_AnyUp) || (keysHeld & HidNpadButton_StickRUp)) {
                if (m_value_edit_index > 0) m_value_edit_index--;
                return true;
            };
            if ((keysDown & HidNpadButton_AnyDown) || (keysHeld & HidNpadButton_StickRDown)) {
                if (m_value_edit_index < keyNames.size() - 1) m_value_edit_index++;
                return true;
            };
            if (keysDown & HidNpadButton_X) {
                m_edit_value = false;
                return true;
            };
            return true;
        }
        if (isKeyComboJustPressed(keysHeld, keysDown, mainMenuChangeToBookmarkCombo)) {
            TeslaFPS = 20;
            IsFrameBackground = false;
            tsl::hlp::requestForeground(false);
            FullMode = false;
            deactivateOriginalFooter = true;
            refresh_cheats = true;
            tsl::changeTo<BookmarkOverlay>();
            dmntchtResumeCheatProcess();
            if (save_code_to_file) dumpcodetofile();
            save_code_to_file = false;
            if (save_breeze_toggle_to_file) save_breeze_toggle();
            save_breeze_toggle_to_file = false;
            if (save_breeze_action_to_file) save_breeze_action();
            save_breeze_action_to_file = false;
            m_cheatlist_offset_save = m_cheatlist_offset;
            // A Gui transition happened; stop here. Without this return the same
            // frame kept falling through the rest of MainMenu::handleInput, so the
            // Y in Y+ZL also fired the plain-Y "find next enabled" handler.
            return true;
        }
        if (isKeyComboJustPressed(keysHeld, keysDown, mainMenuIncreaseFontSizeCombo)) { // font size++
            fontsize++;
            return true;
        }
        if (isKeyComboJustPressed(keysHeld, keysDown, mainMenuDecreaseFontSizeCombo)) { // font size--
            fontsize--;
            return true;
        }
        if (keysDown & HidNpadButton_AnyLeft) { // show outline
            if (m_cursor_on_bookmark && m_cheatCnt > 0) {
                m_show_outline = false;
                m_cursor_on_bookmark = false;
            } else if (m_show_outline) {
                if (m_AttributeDumpBookmark->size() > 0) {
                    m_cursor_on_bookmark = true;
                }
            } else if (m_outline.size() > 1 && !m_outline_mode) 
                m_show_outline = true;
            else if (m_AttributeDumpBookmark->size() > 0) {
                m_cursor_on_bookmark = true;
            }
            return true;
        }
        if (keysDown & HidNpadButton_AnyRight) { // don't show outline
            if (m_cursor_on_bookmark && m_cheatCnt > 0) {
                if (m_outline.size() > 1 && !m_outline_mode) m_show_outline = true;
                m_cursor_on_bookmark = false;
            } else if (m_show_outline) {
                m_cheatlist_offset = m_outline[m_outline_index].index;
                m_cheat_index = 0;
                m_show_outline = false;
            } else if (m_AttributeDumpBookmark->size() > 0) {
                m_cursor_on_bookmark = true;
            }
            return true;
        }
        // Lone X toggles the "show all within outline" view. isInKeyComboList only
        // knows defined combos, so an undefined pair like ZR+X would otherwise
        // leak in here and jump m_cheatlist_offset out of range (emptying the
        // list). Require that no shoulder/trigger key is held, so only a clean
        // X press acts (X+ZL is still routed to the outline-mode combo below).
        if (keysDown & HidNpadButton_X && !(isInKeyComboList(keysHeld, keysDown))
            && !((keysDown | keysHeld) & (HidNpadButton_L | HidNpadButton_R | HidNpadButton_ZL | HidNpadButton_ZR))) { // force switch to outline mode
            if (m_outline_mode) return true;
            if (m_outline.size() > 1) {
                m_showALlCheats = !m_showALlCheats;
                if (m_outline_index >= m_outline.size()) m_outline_index = m_outline.size() - 1;
                m_cheatlist_offset = m_outline[m_outline_index].index;
                if (m_cheatlist_offset >= (u32)m_cheatCnt) m_cheatlist_offset = 0;
                m_cheat_index = 0;
            }
            return true;
        }
        // Switch outline/non-outline mode. isKeyComboJustPressed is edge-triggered
        // (fires once when a combo member goes down), so holding ZL+X can no longer
        // flip m_outline_mode every frame.
        if (isKeyComboJustPressed(keysHeld, keysDown, mainMenuOutlineModeSwitchesCombo)) { // switch to outline/non-outline mode
            m_outline_mode = !m_outline_mode;
            if (m_outline_mode) {
                // Entering outline. The saved position was captured the last
                // time we left outline; in between, m_cheat_outline may have
                // shrunk (group collapsed, cheat deleted, master toggle
                // flipped), so the saved offset/row can be past the end and
                // the render loop's `line + m_cheatlist_offset >= size`
                // check breaks on line 0 -- the user sees an empty list until
                // they nudge the cursor. Clamp to the current size.
                m_showALlCheats = true;
                u32 size = (u32)m_cheat_outline.size();
                if (size == 0) {
                    m_cheat_index = 0;
                    m_cheatlist_offset = 0;
                } else {
                    u32 off = m_cheatlist_offset_save;
                    if (off >= size) off = size - 1;
                    u32 visible = size - off;
                    if (visible > (u32)NUM_cheats) visible = (u32)NUM_cheats;
                    u32 row = m_cheat_index_save;
                    if (row >= visible) row = visible - 1;
                    m_cheatlist_offset = off;
                    m_cheat_index = row;
                }
            } else {
                // Entering flat: stash the outline position and jump the flat
                // base to the raw index of the currently-highlighted outline
                // entry. If the raw is somehow out of range, fall back to the
                // top; the pre-pass additionally recovers from a base landing
                // on a trailing marker (empty window -> reset to 0).
                m_cheat_index_save = m_cheat_index;
                m_cheatlist_offset_save = m_cheatlist_offset;
                m_cheat_index = 0;
                m_cheatlist_offset = (redirect_index < (u32)m_cheatCnt) ? redirect_index : 0;
            }
            return true;
        }
        if (keysDown & HidNpadButton_Y) {  //find next enabled cheat
            // Remember whether we were already in the flat view. If we were,
            // m_flat_row_raw reflects the currently-displayed window and we can
            // just move the cursor there without re-scrolling. If we're coming
            // from outline mode, the map is stale/empty until the next
            // getcheats() rebuild, so always scroll.
            bool was_flat = !m_outline_mode;
            m_show_outline = false;
            m_outline_mode = false;
            m_cursor_on_bookmark = false;
            m_showALlCheats = true;
            if (m_cheatCnt == 0) return true;
            // Resolve the currently highlighted real cheat, then wrap-scan the raw
            // array for the next enabled one. Markers are skipped explicitly (they
            // are bookkeeping, never enabled).
            u32 cur = FlatSelectedRaw();
            u32 start = (cur == 0xFFFFFFFFu) ? 0 : cur;
            u32 found = 0xFFFFFFFFu;
            for (u32 step = 1; step <= (u32)m_cheatCnt; step++) {
                u32 idx = (u32)(((u64)start + step) % m_cheatCnt);
                if (IsSectionBegin(m_cheats[idx]) || IsSectionEnd(m_cheats[idx])) continue;
                if (m_cheats[idx].enabled) { found = idx; break; }
            }
            if (found != 0xFFFFFFFFu) {
                // Gentler jump-to-next-enabled: when the target is already visible
                // in the current window, only move the cursor to its row (no view
                // re-scroll). If it's off-screen, scroll the view so the target
                // lands on the first row. Without this, consecutive Y presses
                // within the same screen visibly "snap" the whole list up each
                // time, and with only one enabled cheat the list appears to jump
                // even though the highlighted item doesn't change.
                u32 rowOfFound = 0xFFFFFFFFu;
                if (was_flat) {
                    for (u32 r = 0; r < m_flat_row_count; r++) {
                        if (m_flat_row_raw[r] == found) { rowOfFound = r; break; }
                    }
                }
                if (rowOfFound != 0xFFFFFFFFu) {
                    m_cheat_index = rowOfFound;
                } else {
                    m_cheatlist_offset = found;
                    m_cheat_index = 0;
                }
            }
            return true;
        }
        if (keysDown & HidNpadButton_B) { // exit outline mode or exit the overlay
            if (!m_outline_mode){
                m_outline_mode = true;
                m_showALlCheats = true;
                m_cheat_index = m_cheat_index_save;
                m_cheatlist_offset = m_cheatlist_offset_save;
                return true;
            }
            if (save_code_to_file) {
                savetoggles();
                dumpcodetofile();
                for (u32 i = 0; i < m_cheatCnt; i++) {
                    dmntchtRemoveCheat(m_cheats[i].cheat_id);
                }
            }
            refresh_cheats = false;
            m_outline_refresh = false;
            save_code_to_file = false;
            if (save_breeze_toggle_to_file) save_breeze_toggle();
            save_breeze_toggle_to_file = false;
            if (save_breeze_action_to_file) save_breeze_action();
            save_breeze_action_to_file = false;
            m_cheatlist_offset_save = 0;
            FullMode = true;
            tsl::hlp::requestForeground(true);
            TeslaFPS = 60;
            deactivateOriginalFooter = false;
            IsFrameBackground = true;
            dmntchtResumeCheatProcess();
            tsl::goBack();
            return true;
        }
        if (m_show_outline && !m_cursor_on_bookmark) {
            if ((keysDown & HidNpadButton_AnyUp) || (keysHeld & HidNpadButton_StickRUp)) { // navigate up
                if (m_outline_index > 0)
                    m_outline_index--;
                else if (m_AttributeDumpBookmark->size() > 0)
                    m_cursor_on_bookmark = true;
                return true;
            }
            if ((keysDown & HidNpadButton_AnyDown) || (keysHeld & HidNpadButton_StickRDown)) { // navigate down
                if (m_outline_index < m_outline.size() - 1) m_outline_index++;
                return true;
            }
            if (keysDown & HidNpadButton_A) { // change to no outline
                m_cheatlist_offset = m_outline[m_outline_index].index;
                m_cheat_index = 0;
                m_show_outline = false;
                return true;
            }
            return true;
        }
        if ((keysDown & HidNpadButton_A) && m_cursor_on_bookmark) { // enter bookmark value editing
            valueStr = _getAddressDisplayString(m_selected_address, m_debugger.get(), m_selected_type);
            value_pos = valueStr.length();
            m_edit_value = true;
            return true;
        }
        if ((keysDown & HidNpadButton_Plus) && !(isInKeyComboList(keysHeld, keysDown)) && !m_cursor_on_bookmark) { // add bookmark
            addbookmark();
            return true;
        }
        if ((keysDown & HidNpadButton_Minus) && m_cursor_on_bookmark) { // remove bookmark
            // Only walk the cursor up when a bookmark was actually removed;
            // deletebookmark() returns false on its empty/out-of-range guards,
            // and in that case the list is unchanged and the cursor must not move.
            if (deletebookmark()) {
                if (((m_index >= NUM_bookmark) || ((m_index + m_addresslist_offset) >= (m_AttributeDumpBookmark->size() / sizeof(bookmark_t) ))) && m_index > 0) m_index--;
            }
            return true;
        }
        // Cheat deletion is destructive: the exit path's dumpcodetofile() rewrites
        // the .txt library from the remaining set. A timestamped .txt.bak is written
        // before that rewrite as a last-resort restore point (see dumpcodetofile).
        if ((keysDown & HidNpadButton_Minus) && !m_cursor_on_bookmark) { // remove cheat
            if (m_outline_mode) {
                if (m_cheat_outline.empty()) return true;
                u32 oi = m_cheat_index + m_cheatlist_offset;
                if (oi >= m_cheat_outline.size()) oi = (u32)m_cheat_outline.size() - 1;
                auto outline_entry = m_cheat_outline[oi];
                if (outline_entry.is_outline && !outline_entry.always_expanded) {
                    for (auto i = outline_entry.index; i <= outline_entry.index + outline_entry.size; i++)
                        dmntchtRemoveCheat(m_cheats[i].cheat_id);
                } else
                    dmntchtRemoveCheat(m_cheats[outline_entry.index].cheat_id);
                // Structure changed: cheat indices shift, so drop remembered
                // expansion rather than re-apply it onto the wrong sections.
                m_expanded_groups.clear();
                m_outline_refresh = true;
                refresh_cheats = true;
                getcheats();
                save_code_to_file = true;
                m_cheatlist_offset = 0;
                m_cheat_index = 0;
                while (m_cheat_index + m_cheatlist_offset + 1 < m_cheat_outline.size()) {
                    if (m_cheat_outline[m_cheat_index + m_cheatlist_offset + 1].index > redirect_index) break;
                    if (m_cheat_index + 1 < m_NUM_cheats)
                        m_cheat_index++;
                    else
                        m_cheatlist_offset++;
                }
            } else {
                dmntchtRemoveCheat(m_cheats[redirect_index].cheat_id);
                m_expanded_groups.clear();
                m_outline_refresh = true;
                refresh_cheats = true;
                getcheats();
                save_code_to_file = true;
                m_cheatlist_offset_save = 0;
                m_cheat_index_save = 0;
                while (m_cheat_index_save + m_cheatlist_offset_save + 1 < m_cheat_outline.size()) {
                    if (m_cheat_outline[m_cheat_index_save + m_cheatlist_offset_save + 1].index > redirect_index) break;
                    if (m_cheat_index_save + 1 < m_NUM_cheats)
                        m_cheat_index_save++;
                    else
                        m_cheatlist_offset_save++;
                }
            }
            return true;
        }
        if ((keysDown & HidNpadButton_AnyUp) || (keysHeld & HidNpadButton_StickRUp)) { // navigate up
            if (m_cursor_on_bookmark) {
                if (m_index > 0) m_index--;
            } else {
                m_cheat_index = std::min(m_cheat_index, m_NUM_cheats);
                if (m_outline.size() > 1 && m_outline[m_outline_index].index + m_cheats[0].cheat_id == m_cheats[m_cheat_index + m_cheatlist_offset].cheat_id) {
                    if (m_showALlCheats){
                        if (m_outline_index > 0)
                            m_outline_index--;
                    } else
                        return true;
                }
                if (m_cheat_index > 0)
                    m_cheat_index--;
                else {
                    if (m_cheatlist_offset > 0)
                        m_cheatlist_offset--;
                    else
                        if (m_AttributeDumpBookmark->size() > 0) m_cursor_on_bookmark = true;
                }
            }
            return true;
        }
        if ((keysDown & HidNpadButton_AnyDown) || (keysHeld & HidNpadButton_StickRDown)) { // navigate down
            // Outline: logical row into m_cheat_outline. Flat: the last real cheat
            // (marker-free), NOT the raw m_cheatCnt -- m_cheatCnt counts section
            // markers, so using it let the cursor scroll past the final cheat.
            u32 m_cheatlineCnt = (m_outline_mode) ? m_cheat_outline.size() : m_last_real_raw + 1;
            if (m_cursor_on_bookmark) {
                if ((m_index < NUM_bookmark - 1) && ((m_index + m_addresslist_offset) < (m_AttributeDumpBookmark->size() / sizeof(bookmark_t) - 1))) m_index++;
                else if (m_cheatlineCnt > 0)
                    m_cursor_on_bookmark = false;
            } else {
                m_cheat_index = std::min(m_cheat_index, (u32)(m_NUM_cheats - (u32)1));
                if (m_outline.size() > 1 && m_outline_index < (m_outline.size() - 1) && m_outline[m_outline_index + 1].index == m_cheats[m_cheat_index + m_cheatlist_offset].cheat_id + 1 - m_cheats[0].cheat_id) {
                    if (m_showALlCheats) {
                        if (m_outline_index < m_outline.size() - 1)
                            m_outline_index++;
                    } else
                        return true;
                }
                if ((m_cheat_index < NUM_cheats - 1) && ((m_cheat_index + m_cheatlist_offset) < m_cheatlineCnt - 1)) m_cheat_index++;
                else if ((m_cheat_index + m_cheatlist_offset) < m_cheatlineCnt - 1)
                    m_cheatlist_offset++;
            }
            return true;
        }
        if (isKeyComboJustPressed(keysHeld, keysDown, mainMenuSetBookmarkMultipier) && m_cursor_on_bookmark) { // set bookmark multipier
            bookmark_t bookmark;
            m_AttributeDumpBookmark->getData((m_index + m_addresslist_offset) * sizeof(bookmark_t), &bookmark, sizeof(bookmark_t));
            if (bookmark.magic!=0x1289) bookmark.multiplier = 1;
            if (keysDown & HidNpadButton_R) {
                switch (bookmark.multiplier) {
                    case 1:
                        bookmark.multiplier = 2;
                        break;
                    case 2:
                        bookmark.multiplier = 4;
                        break;
                    case 4:
                        bookmark.multiplier = 8;
                        break;
                    case 8:
                        bookmark.multiplier = 16;
                        break;
                    case 16:
                        bookmark.multiplier = 32;
                        break;
                    case 32:
                        break;
                    default:
                        bookmark.multiplier = 1;
                        break;
                }
            } else {
                switch (bookmark.multiplier) {
                    case 32:
                        bookmark.multiplier = 16;
                        break;
                    case 16:
                        bookmark.multiplier = 8;
                        break;
                    case 8:
                        bookmark.multiplier = 4;
                        break;
                    case 4:
                        bookmark.multiplier = 2;
                        break;
                    default:
                        bookmark.multiplier = 1;
                        break;
                }
            }
			bookmark.magic = 0x1289;
            m_AttributeDumpBookmark->putData((m_index + m_addresslist_offset) * sizeof(bookmark_t), &bookmark, sizeof(bookmark_t));
            return true;
        }
        if ((keysDown & HidNpadButton_A) && m_cheatCnt > 0 && !m_cursor_on_bookmark) { //*** toggle cheats / expand outline
            u32 index = m_cheat_index + m_cheatlist_offset;
            if (m_outline_mode) {
                if (m_cheat_outline.empty()) return true;
                if (index >= m_cheat_outline.size()) index = (u32)m_cheat_outline.size() - 1;
                auto entry = m_cheat_outline[index];
                if (entry.is_outline) {
                    // A group header is a --SectionStart marker (a no-op cheat): A
                    // only expands/collapses it and must never toggle the marker
                    // itself (that would flip a phantom cheat and bump the enabled
                    // count). Expansion is recorded in m_expanded_groups and the
                    // outline is rebuilt from it, so a collapsed group can never
                    // keep a stale child row (e.g. one just enabled) visible.
                    if (!entry.always_expanded) {
                        if (entry.expanded)
                            std::erase(m_expanded_groups, entry.index);
                        else
                            m_expanded_groups.push_back(entry.index);
                        m_outline_refresh = true;
                        refresh_cheats = true;
                    }
                    return true;
                }
                index = entry.index;
            } else {
                // Flat view: resolve the highlighted real cheat through the row
                // map, which already excludes section markers, so A can never land
                // on (or toggle) a marker row.
                index = FlatSelectedRaw();
                if (index == 0xFFFFFFFFu)
                    return true;
            }
            // Safety net: never toggle a section marker.
            if (IsSectionBegin(m_cheats[index]) || IsSectionEnd(m_cheats[index])) return true;
            if (m_cheats[index].enabled)
                dmntchtToggleCheat(m_cheats[index].cheat_id);
            else {
                if (m_cheats[index].definition.num_opcodes + total_opcode <= MaximumProgramOpcodeCount)
                    dmntchtToggleCheat(m_cheats[index].cheat_id);
            }
            save_toggles_to_file = true;
            refresh_cheats = true;
            return true;
        }
        if (isKeyComboJustPressed(keysHeld, keysDown, mainMenuNextLabel)) {  // Next label
            if (m_outline_mode) {
                auto i = m_cheat_index + m_cheatlist_offset;
                // The old loop tested `i < size` and then did `i++` before
                // indexing, so when the cursor was at the last outline it read
                // m_cheat_outline[size] (out of bounds). Bound on i+1 instead.
                while (i + 1 < m_cheat_outline.size()) {
                    i++;
                    if (m_cheat_outline[i].is_outline) {
                        m_cheatlist_offset = i - m_cheat_index;
                        break;
                    }
                }
            }
            return true;
        }
        if (isKeyComboJustPressed(keysHeld, keysDown, mainMenuPreviousLabel)) {  // Previous label
            if (m_outline_mode) {
                auto i = m_cheat_index + m_cheatlist_offset;
                while (i > 0) {
                    i--;
                    if (m_cheat_outline[i].is_outline) {
                        if (i >= m_cheat_index)
                            m_cheatlist_offset = i - m_cheat_index;
                        else {
                            m_cheatlist_offset = 0;
                            m_cheat_index = i;
                        }
                        break;
                    }
                }
            }
            return true;
        }
        if (keysDown & HidNpadButton_R && !(isInKeyComboList(keysHeld, keysDown))) {  //page down
            if (m_outline_mode) {
                if ((m_cheatlist_offset + NUM_cheats) < m_cheat_outline.size() - 1) m_cheatlist_offset += NUM_cheats;
                if ((m_cheat_index + m_cheatlist_offset) > m_cheat_outline.size() - 1) m_cheat_index = m_cheat_outline.size() - 1 - m_cheatlist_offset;
                return true;
            }
            if (!m_cursor_on_bookmark && (m_outline.size() <= 1 || m_showALlCheats)) {
                if ((m_cheatlist_offset + NUM_cheats) < m_cheatCnt - 1) m_cheatlist_offset += NUM_cheats;
                if ((m_cheat_index + m_cheatlist_offset) > m_cheatCnt - 1) m_cheat_index = m_cheatCnt - 1 - m_cheatlist_offset;
                size_t i = 0;
                while (i < m_outline.size() && (m_cheat_index + m_cheatlist_offset) > m_outline[i].index) {
                    m_outline_index = i;
                    i++;
                }

            } else if (!m_cursor_on_bookmark && m_outline.size() > 1) {  // show within outline only case
                if (m_outline_index < m_outline.size() - 1) m_outline_index++;
                m_cheatlist_offset = m_outline[m_outline_index].index;
                m_cheat_index = 0;
            };
            return true;
        }
        if (keysDown & HidNpadButton_L && !(isInKeyComboList(keysHeld, keysDown))) {  //page up
            if (!m_cursor_on_bookmark && (m_outline.size() <= 1 || m_showALlCheats)) {
                if (m_cheatlist_offset > NUM_cheats)
                    m_cheatlist_offset -= NUM_cheats;
                else
                    m_cheatlist_offset = 0;
                size_t i = 0;
                while (i < m_outline.size() && (m_cheat_index + m_cheatlist_offset) > m_outline[i].index) {
                    m_outline_index = i;
                    i++;
                }
            } else if (!m_cursor_on_bookmark && m_outline.size() > 1) {  // show within outline only case
                if (m_outline_index > 0) m_outline_index--;
                m_cheatlist_offset = m_outline[m_outline_index].index;
                m_cheat_index = 0;
            }
            return true;
        }

        return false;
    }
};

class MonitorOverlay : public tsl::Overlay {
   public:
    virtual void initServices() override {
        fsdevMountSdmc();
        std::string jsonStr = R"(
            {
                "PluginName": "Zing",
                "LoadFailedLoadCacheFromFileDmntCheatEntryText": " fail to load",
                "CodeBiggerThanBookmarkErrorAddBookmarkCheatsLabelsStrText": "this code is bigger than space catered on the bookmark !!\n",
                "CheatWrongWidthValueProcessErrorAddBookmarkCheatsLabelsStrText": "cheat code processing error, wrong width value\n",
                "AddPointerChainToBookmarkErrorAddBookmarkCheatsLabelsStrText": "Adding pointer chain from cheat to bookmark\n",
                "NoAvailableCheatsErrorGetCheatsCheatsEnableStrText": "No Cheats available\n",
                "BasicInfoGetCheatsCheatsCursorText": "Cheat id = %d, Total enabled = %d/%ld\n",
                "PressKeyForComboCountGetCheatsCheatsLabelsStrText": "Press key for combo count = %d\n",
                "OutlineClosedGetCheatsCheatsLabelsStrText": "- outline off - [%s]\n",
                "EnabledCheatsGetCheatsCheatsLabelsStrText": "Enabled Cheats %d\n",
                "ShowTotalInfoGetCheatsCheatsCursorText": "Cheats %d/%ld opcode = %d Total opcode = %d/%d\n",
                "UpdateStatusTitleStrBookmarkOverlayCustomDrawerText": "\uE0A6+\uE0A4/\uE0A5 Font size  \uE0A6+\uE0A3 Edit  \uE0C4+\uE0C5 Exit\n",
                "GameNotRunningMainMenuListItemText": "Game not running",
                "NoDmntMainMenuListItemText": "Dmnt not attached",
                "UpdateCursorNoCheatsMainMenuCustomDrawerText": "%s v%s\nPID: %03ld TID: %016lX BID: %02X%02X%02X%02X%02X%02X%02X%02X\n\n\n\n",
                "UpdateCursorOnBookmarkMainMenuCustomDrawerText": "%s v%s\nPID: %03ld TID: %016lX BID: %02X%02X%02X%02X%02X%02X%02X%02X\n\uE092\uE093\uE091\uE090 nav\n\uE0A4 \uE0A5 Change  \uE0A0 Edit  \uE0A1 Exit  \uE0A6+\uE0A4/\uE0A5 Font size  \uE0B4 Delete\n\uE0A6+\uE04E Toggle show all cheats  \uE0A3 Find next enabled cheat\n",
                "UpdateCursorNotOnBookmarkMainMenuCustomDrawerText": "%s v%s\nPID: %03ld TID: %016lX BID: %02X%02X%02X%02X%02X%02X%02X%02X\n\uE092\uE093\uE091\uE090\uE0A4\uE0A5 nav\n\uE0A0 Toggle  \uE0B3 Add bookmark  \uE0B4 Delete (irreversible)  \uE0A1 Exit  \uE0A6+\uE0A4/\uE0A5 Font size\n\uE0A6+\uE04E Toggle show all cheats  \uE0A3 Find next enabled cheat\n",
                "UpdateEditValueHeaderMainMenuCustomDrawerText": "%s v%s\nPID: %03ld TID: %016lX BID: %02X%02X%02X%02X%02X%02X%02X%02X\n\n\n\n",
                "UpdateBookmarkPressKeyForComboCountMainMenuCustomDrawerText": "Press key for combo count = %d\n",
                "UpdateEditCheatValueMainMenuCustomDrawerText": "\uE092\uE093\uE0A4\uE0A5 \uE0A0 Select, \uE0A1 Backspace, \uE045 Enter, \uE0A2 Cancel\n",
                "UpdateShowOutlineCursorMainMenuCustomDrawerText": "Cheats outline \uE092\uE093 \uE0A0 Select\n"
            }
        )";
        std::string lanPath = std::string("sdmc:/switch/.overlays/lang/") + APPTITLE + "/";
        tsl::hlp::doWithSmSession([&lanPath, &jsonStr]{
            tsl::tr::InitTrans(lanPath, jsonStr);
        });
        dmntchtInitialize();
        nsInitialize();
        if (init_se_tools()) {
            load_breeze_toggle();
            load_breeze_action();
        }
        //Initialize services
    }

    virtual void exitServices() override {
        //Exit services
        cleanup_se_tools();
        dmntchtExit();
        nsExit();
        fsdevUnmountDevice("sdmc");
    }

    virtual std::unique_ptr<tsl::Gui> loadInitialGui() override {
        return initially<MainMenu>();  // Initial Gui to load. It's possible to pass arguments to it's constructor like this
    }
};

// This function gets called on startup to create a new Overlay object
int main(int argc, char **argv) {
    tsl::hlp::doWithSDCardHandle([] {
		ParseIniFile();
	});

    return tsl::loop<MonitorOverlay>(argc, argv);
}
