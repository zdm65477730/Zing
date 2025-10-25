#define TESLA_INIT_IMPL
#include <tesla.hpp>

#include "debugger.hpp"
#include "dmntcht.h"
#include "memory_dump.hpp"
#include "utils.hpp"

using namespace tsl;

bool dmnt_present = false;

char Variables[672];

struct toggle_list_t {
    u32 keycode;
    u32 cheat_id;
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
} cheat_outline_entry_t;
std::vector<cheat_outline_entry_t> m_cheat_outline;
bool m_outline_mode = true;
bool m_outline_refresh = true;
bool show_outline_off = false;
#define NUM_bookmark 10
#define MAX_NUM_cheats 35
u32 m_NUM_cheats = 20;
#define NUM_cheats m_NUM_cheats
#define NUM_combokey 3
u32 total_opcode = 0;
#define MaxCheatCount 0x80
#define MaxOpcodes 0x100
#define MaximumProgramOpcodeCount 0x400
u8 fontsize = 14;
bool m_editCheat = false;
u8 keycount;
Result rc;
std::string m_titleName = "", m_titleName2 = "", m_versionString = "";
char m_cheatcode_path[128];
char m_toggle_path[128];
u64 m_cheatCnt = 0; 
DmntCheatEntry *m_cheats = nullptr;
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
Debugger *m_debugger;
MemoryDump *m_AttributeDumpBookmark = nullptr;
u8 m_addresslist_offset = 0;
u32 m_cheatlist_offset = 0, m_cheatlist_offset_save = 0;
bool m_32bitmode = false;
static const std::vector<u8> dataTypeSizes = {1, 1, 2, 2, 4, 4, 8, 8, 4, 8, 8};
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

    m_debugger = new Debugger();
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
        return false;
    }

    memcpy(build_id, metadata.main_nso_build_id, 0x20);

    snprintf(bookmarkfilename, 200, "%s/%02x%02x%02x%02x%02x%02x%02x%02x.dat", EDIZON_DIR,
             build_id[0], build_id[1], build_id[2], build_id[3], build_id[4], build_id[5], build_id[6], build_id[7]);

    m_AttributeDumpBookmark = new MemoryDump(bookmarkfilename, DumpType::ADDR, false);

    return true;
}

void cleanup_se_tools() {
    if (m_debugger) {
        delete m_debugger;
        m_debugger = nullptr;
    }

    if (m_AttributeDumpBookmark) {
        delete m_AttributeDumpBookmark;
        m_AttributeDumpBookmark = nullptr;
    }
}

void dumpcodetofile() {
    FILE *pfile;
    char tmp[1000];
    if (build_id[0] == 0x0 && build_id[1] == 0x0 && build_id[2] == 0x0 && build_id[3] == 0x0 && build_id[4] == 0x0 && build_id[5] == 0x0 && build_id[6] == 0x0 && build_id[7])
        return;
    snprintf(m_cheatcode_path, 128, "sdmc:/atmosphere/contents/%016lX/cheats/%02X%02X%02X%02X%02X%02X%02X%02X.txt", metadata.title_id, build_id[0], build_id[1], build_id[2], build_id[3], build_id[4], build_id[5], build_id[6], build_id[7]);
    snprintf(m_toggle_path, 128, "sdmc:/atmosphere/contents/%016lX/cheats/toggles.txt", metadata.title_id);
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

            if ((i == 0) && (m_cheats[0].cheat_id == 0))
                snprintf(tmp, 1000, "{%s}\n", m_cheats[i].definition.readable_name);
            else
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
                        // 3+1
                    case 9:
                    case 0xC04:
                        // 2+1
                        snprintf(tmp, sizeof(tmp), "%08X ", m_cheats[i].definition.opcodes[j++]);
                        fputs(tmp, pfile);
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
                    case 5:
                    case 7:
                    case 0xC00:
                    case 0xC02:
                        snprintf(tmp, sizeof(tmp), "%08X ", m_cheats[i].definition.opcodes[j++]);
                        fputs(tmp, pfile);
                        // 2
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

void save_breeze_toggle() {
    std::string breeze_toggle_filename = bookmarkfilename;
    breeze_toggle_filename.replace((breeze_toggle_filename.length()-3), 3, "bz1");
    MemoryDump *breeze_toggle_file;
    breeze_toggle_file = new MemoryDump(breeze_toggle_filename.c_str(), DumpType::ADDR, true);
    for (auto entry : m_toggle_list) {
        breeze_toggle_file->addData((u8 *)&entry, sizeof(toggle_list_t));
    }
    delete breeze_toggle_file;
}

void load_breeze_toggle() {
    m_toggle_list.clear();
    std::string breeze_toggle_filename = bookmarkfilename;
    breeze_toggle_filename.replace((breeze_toggle_filename.length()-3), 3, "bz1");
    MemoryDump *breeze_toggle_file;
    toggle_list_t entry;
    breeze_toggle_file = new MemoryDump(breeze_toggle_filename.c_str(), DumpType::ADDR, false);
    if (breeze_toggle_file->size() > 0)
        for (size_t i = 0; i < breeze_toggle_file->size() / sizeof(toggle_list_t); i++) {
            breeze_toggle_file->getData(i * sizeof(toggle_list_t), &entry, sizeof(toggle_list_t));
            m_toggle_list.push_back(entry);
        }
    delete breeze_toggle_file;
}

void save_breeze_action() {
    std::string breeze_action_filename = bookmarkfilename;
    breeze_action_filename.replace((breeze_action_filename.length()-3), 3, "bz2");
    MemoryDump *breeze_acton_file;
    breeze_acton_file = new MemoryDump(breeze_action_filename.c_str(), DumpType::ADDR, true);
    for (auto entry : m_breeze_action_list) {
        breeze_acton_file->addData((u8 *)&entry, sizeof(breeze_action_list_t));
    }
    delete breeze_acton_file;
}

void load_breeze_action() {
    m_breeze_action_list.clear();
    std::string breeze_action_filename = bookmarkfilename;
    breeze_action_filename.replace((breeze_action_filename.length()-3), 3, "bz2");
    MemoryDump *breeze_acton_file;
    breeze_action_list_t entry;
    breeze_acton_file = new MemoryDump(breeze_action_filename.c_str(), DumpType::ADDR, false);
    if (breeze_acton_file->size() > 0)
        for (size_t i = 0; i < breeze_acton_file->size() / sizeof(breeze_action_list_t); i++) {
            breeze_acton_file->getData(i * sizeof(breeze_action_list_t), &entry, sizeof(breeze_action_list_t));
            m_breeze_action_list.push_back(entry);
        }
    delete breeze_acton_file;
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
        size_t len = ftell(pfile);
        u8 *s = new u8[len];
        fseek(pfile, 0, SEEK_SET);
        fread(s, 1, len, pfile);
        fclose(pfile); 
        if (copy_cheat_file) {
            pfile2 = fopen(m_cheatcode_path, "wb");
            if (pfile2 != NULL) {
                fwrite(s, 1, len, pfile2);
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
                while (s[j] != ']') {
                    j++;
                    if (j >= len) {
                        return false;
                    }
                }
                /* s[i+1:j] is cheat name. */
                const size_t cheat_name_len = std::min(j - i - 1, sizeof(cheatentry.definition.readable_name));
                std::memcpy(cheatentry.definition.readable_name, &s[i + 1], cheat_name_len);
                for (u32 i = 0; i < cheat_name_len; i++) {
                    if (cheatentry.definition.readable_name[i] == 13 || cheatentry.definition.readable_name[i] == 10) cheatentry.definition.readable_name[i] = 32;
                };
                cheatentry.definition.readable_name[cheat_name_len] = 0;
                label_len = cheat_name_len;

                /* Skip onwards. */
                i = j + 1;
            } else if (s[i] == '(') {
                size_t j = i + 1;
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
                while (s[j] != '}') {
                    j++;
                    if (j >= len) {
                        return false;
                    }
                }

                /* s[i+1:j] is cheat name. */
                const size_t cheat_name_len = std::min(j - i - 1, sizeof(cheatentry.definition.readable_name));
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
        strcat(m_cheatcode_path, "LoadFailedLoadCacheFromFileDmntCheatEntryText"_tr.c_str());
        strcpy((centry.definition.readable_name), m_cheatcode_path);
        m_cache.push_back(centry);
        m_cache_outline.push_back(entry);
    }
    return false;
}

bool loadcheatsfromfile() {
    if (build_id[0] == 0x0 && build_id[1] == 0x0 && build_id[2] == 0x0 && build_id[3] == 0x0 && build_id[4] == 0x0 && build_id[5] == 0x0 && build_id[6] == 0x0 && build_id[7])
        return false;

    m_outline.clear();
    u8 _index = 0;
    u8 last_entry = 0xFF;

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
        size_t len = ftell(pfile);
        u8 *s = new u8[len];
        fseek(pfile, 0, SEEK_SET);
        fread(s, 1, len, pfile);
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
                while (s[j] != ']') {
                    j++;
                    if (j >= len) {
                        return false;
                    }
                }
                /* s[i+1:j] is cheat name. */
                const size_t cheat_name_len = std::min(j - i - 1, sizeof(cheatentry.definition.readable_name));
                std::memcpy(cheatentry.definition.readable_name, &s[i + 1], cheat_name_len);
                for (u32 i = 0; i < cheat_name_len; i++) {
                    if (cheatentry.definition.readable_name[i] == 13 || cheatentry.definition.readable_name[i] == 10) cheatentry.definition.readable_name[i] = 32;
                };
                cheatentry.definition.readable_name[cheat_name_len] = 0;
                label_len = cheat_name_len;

                /* Skip onwards. */
                i = j + 1;
            } else if (s[i] == '(') {
                size_t j = i + 1;
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
                while (s[j] != '}') {
                    j++;
                    if (j >= len) {
                        return false;
                    }
                }

                /* s[i+1:j] is cheat name. */
                const size_t cheat_name_len = std::min(j - i - 1, sizeof(cheatentry.definition.readable_name));
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

bool ParseCheatToggles(const char *s, size_t len) {
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
            while (s[j] != ']') {
                j++;
                if (j >= len) {
                    return false;
                }
            }
            /* s[i+1:j] is cheat name. */
            const size_t cheat_name_len = std::min(j - i - 1, sizeof(cur_cheat_name));
            std::memcpy(cur_cheat_name, &s[i + 1], cheat_name_len);
            cur_cheat_name[cheat_name_len] = 0;
            /* Skip onwards. */
            i = j + 1;
            /* Skip whitespace. */
            while (std::isspace(static_cast<unsigned char>(s[i]))) {
                i++;
            }
            /* Parse whether to toggle. */
            j = i + 1;
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
        size_t len = ftell(pfile);
        char *s = new char[len];
        fseek(pfile, 0, SEEK_SET);
        fread(s, 1, len, pfile);
        ParseCheatToggles(s, len);
        fclose(pfile);
    }
}

void savetoggles() {
    snprintf(m_toggle_path, 128, "sdmc:/atmosphere/contents/%016lX/cheats/toggles.brz", metadata.title_id);
    FILE *pfile;
    char tmp[1000];
    pfile = fopen(m_toggle_path, "w");
    if (pfile != NULL) {
        for (u8 i = 0; i < m_cheatCnt; i++) {
            snprintf(tmp, 1000, "[%s]\n%s\n", m_cheats[i].definition.readable_name, (m_cheats[i].enabled) ? "true" : "false");
            fputs(tmp, pfile);
        }
        fclose(pfile);
    }
}

static std::string _getAddressDisplayString(u64 address, Debugger *debugger, searchType_t searchType) {
    char ss[200];

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
    old_bookmarkfilename.replace((old_bookmarkfilename.length()-3),3,"old");
    MemoryDump *m_old_AttributeDumpBookmark;
    m_old_AttributeDumpBookmark = new MemoryDump(old_bookmarkfilename.c_str(), DumpType::ADDR, true);
    for (size_t i = 0; i < m_AttributeDumpBookmark->size() / sizeof(bookmark_t); i++) {
        {
            m_AttributeDumpBookmark->getData(i * sizeof(bookmark_t), &bookmark, sizeof(bookmark_t));
            m_old_AttributeDumpBookmark->addData((u8 *)&bookmark, sizeof(bookmark_t));
        }
    }
    delete m_AttributeDumpBookmark;
    m_AttributeDumpBookmark = new MemoryDump(bookmarkfilename, DumpType::ADDR, true);
    for (size_t i = 0; i < m_old_AttributeDumpBookmark->size() / sizeof(bookmark_t); i++) {
        if (i != m_index + m_addresslist_offset) {
            m_old_AttributeDumpBookmark->getData(i * sizeof(bookmark_t), &bookmark, sizeof(bookmark_t));
            m_AttributeDumpBookmark->addData((u8 *)&bookmark, sizeof(bookmark_t));
        }
    }
    delete m_old_AttributeDumpBookmark;
    return true;
}

bool addbookmark() {
    u32 index = m_cheat_index + m_cheatlist_offset;
    if (m_outline_mode) {
        index = m_cheat_outline[index].index;
    }
    DmntCheatDefinition cheat = m_cheats[index].definition;
    bookmark_t bookmark;
    memcpy(&bookmark.label, &cheat.readable_name, sizeof(bookmark.label));
    if ((bookmark.label[18] & 0xC0) == 0xC0) {
        bookmark.label[18] = 0;
    } else if ((bookmark.label[17] & 0xE0) == 0xE0) {
        bookmark.label[17] = 0;
        bookmark.label[18] = 0;
    } else if ((bookmark.label[16] & 0xF0) == 0xF0) {
        bookmark.label[16] = 0;
        bookmark.label[17] = 0;
        bookmark.label[18] = 0;
    }
    bookmark.pointer.depth = 0;
    bookmark.deleted = false;
    bool success = false;
    u64 offset[MAX_POINTER_DEPTH + 1] = {0};
    u64 depth = 0;
    bool no7 = true;

    for (u8 i = 0; i < cheat.num_opcodes; i++) {
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
                    if (((cheat.opcodes[i + 2] & 0xF0000000) == 0x40000000) || ((cheat.opcodes[i + 2] & 0xF0000000) == 0x30000000) || ((cheat.opcodes[i + 2] & 0xF0000000) == 0xC0000000))
                        bookmark.type = SEARCH_TYPE_FLOAT_32BIT;
                    break;
                case 8:
                    bookmark.type = SEARCH_TYPE_UNSIGNED_64BIT;
                    if (((cheat.opcodes[i + 1] & 0xF0000000) == 0x40000000) || ((cheat.opcodes[i + 1] & 0xF0000000) == 0x30000000) || ((cheat.opcodes[i + 1] & 0xF0000000) == 0xC0000000))
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
                if (m_32bitmode)
                    m_debugger->readMemory(&nextaddress, sizeof(u32), nextaddress);
                else
                    m_debugger->readMemory(&nextaddress, sizeof(u64), nextaddress);
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
        if (m_cheatCnt != 0) {
            delete m_cheats;
            m_cheats = nullptr;
        }
        dmntchtGetCheatCount(&m_cheatCnt);
        if (m_cheatCnt == 0) {
            loadcheatsfromfile();
            dmntchtGetCheatCount(&m_cheatCnt);
        }
        if (m_cheatCnt > 0) {
            m_cheats = new DmntCheatEntry[m_cheatCnt];
            dmntchtGetCheats(m_cheats, m_cheatCnt, 0, &m_cheatCnt);
        } else {
            CheatsLabelsStr[0] = 0;
            CheatsEnableStr[0] = 0;
            snprintf(CheatsEnableStr, sizeof CheatsEnableStr, "NoAvailableCheatsErrorGetCheatsCheatsEnableStrText"_tr.c_str());
            cheat_outline_entry_t outline_entry = {};
            m_cheat_outline.push_back(outline_entry);
            return;
        }
        refresh_cheats = false;
        // make outline
        if (m_outline_refresh) {
            m_outline_refresh = false;    
            bool hide_entry = false;
            m_cheat_outline.clear();
            cheat_outline_entry_t cheat_outline_entry = {};
            for (u32 i = 0; i < m_cheatCnt; i++) {
                auto entry = m_cheats[i];
                if (entry.definition.opcodes[0] == 0x20000000 || entry.definition.opcodes[0] == 0x20000001) { // 0x20000001 is end outline code
                    if (cheat_outline_entry.is_outline) {
                        cheat_outline_entry.size = i - cheat_outline_entry.index - 1;
                        m_cheat_outline.push_back(cheat_outline_entry);
                    }
                    cheat_outline_entry.index = i;
                    cheat_outline_entry.is_outline = true;
                    if (entry.definition.opcodes[0] == 0x20000000) {
                        cheat_outline_entry.always_expanded = false;
                        cheat_outline_entry.expanded = false;
                        hide_entry = true;
                    } else {
                        cheat_outline_entry.expanded = true;
                        cheat_outline_entry.always_expanded = true;
                        if (show_outline_off) m_cheat_outline.push_back(cheat_outline_entry); // comment out this line to not show this type of outline
                        hide_entry = false;
                    }
                } else if (!hide_entry) {
                    cheat_outline_entry.index = i;
                    cheat_outline_entry.is_outline = false;
                    m_cheat_outline.push_back(cheat_outline_entry);
                }
            }
            if (cheat_outline_entry.is_outline) {
                cheat_outline_entry.size = m_cheatCnt - 1 - cheat_outline_entry.index;
                m_cheat_outline.push_back(cheat_outline_entry);
            };
        }
    }
    if (m_outline_mode && !m_show_only_enabled_cheats) { // take over and ignore the rest
        CheatsLabelsStr[0] = 0;
        CheatsCursor[0] = 0;
        CheatsEnableStr[0] = 0;
        snprintf(CheatsLabelsStr, sizeof CheatsLabelsStr, "\n");
        snprintf(CheatsEnableStr, sizeof CheatsEnableStr, "\n");
        u32 Enable_count = 0;
        for (u8 i = 0; i < m_cheatCnt; i++)
            if (m_cheats[i].enabled) Enable_count++;
        snprintf(CheatsCursor, sizeof CheatsCursor, "BasicInfoGetCheatsCheatsCursorText"_tr.c_str(), m_cheats[m_cheat_outline[m_cheat_index + m_cheatlist_offset].index].cheat_id, Enable_count, m_cheatCnt);
        for (u8 line = 0; line < NUM_cheats; line++) {
            if ((line + m_cheatlist_offset) >= m_cheat_outline.size())
                break;
            {
                DmntCheatEntry cheat_entry = m_cheats[m_cheat_outline[line + m_cheatlist_offset].index];
                char namestr[100] = "";
                char toggle_str[100] = "";
                if (!m_show_only_enabled_cheats) {
                    for (size_t i = 0; i < m_toggle_list.size(); i++) {
                        if (m_toggle_list[i].cheat_id == m_cheats[line + m_cheatlist_offset].cheat_id) {
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
                    if (cheat_entry.definition.opcodes[0] == 0x20000000) {
                        snprintf(ss, sizeof ss, "[%s%s %s] %d\n", namestr, cheat_entry.definition.readable_name, toggle_str, m_cheat_outline[line + m_cheatlist_offset].size);
                        strcat(CheatsLabelsStr, "\n");
                        strcat(CheatsEnableStr, ss);
                    } else if (cheat_entry.definition.opcodes[0] == 0x20000001) {
                        snprintf(ss, sizeof ss, "OutlineClosedGetCheatsCheatsLabelsStrText"_tr.c_str(), cheat_entry.definition.readable_name);
                        strcat(CheatsLabelsStr, "\n");
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
        for (u8 i = 0; i < m_cheatCnt; i++)
            if (m_cheats[i].enabled) total_opcode += m_cheats[i].definition.num_opcodes;
        snprintf(CheatsCursor, sizeof CheatsCursor, "ShowTotalInfoGetCheatsCheatsCursorText"_tr.c_str(), m_cheat_index + m_cheatlist_offset + 1, m_cheatCnt, m_cheats[m_cheat_index + m_cheatlist_offset].definition.num_opcodes, total_opcode, MaximumProgramOpcodeCount);
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
        while (m_show_only_enabled_cheats && !(m_cheats[line + m_cheatlist_offset].enabled)){
             m_cheatlist_offset ++;
             if ((line + m_cheatlist_offset) >= m_cheatCnt)
                 break;
        }
        if ((line + m_cheatlist_offset) >= m_cheatCnt)
            break;
        if (!m_showALlCheats && m_outline_index < (m_outline.size() - 1) && m_outline[m_outline_index + 1].index  < m_cheats[line + m_cheatlist_offset].cheat_id + 1 - m_cheats[0].cheat_id) break;
        {   
            char namestr[100] = "";
            char toggle_str[100] = "";
            if (!m_show_only_enabled_cheats) {
                for (size_t i = 0; i < m_toggle_list.size(); i++) {
                    if (m_toggle_list[i].cheat_id == m_cheats[line + m_cheatlist_offset].cheat_id) {
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
            int buttoncode = m_cheats[line + m_cheatlist_offset].definition.opcodes[0];
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
                if (m_cheats[line + m_cheatlist_offset].definition.opcodes[0] == 0x20000000) {
                    snprintf(ss, sizeof ss, "[%s%s %s]\n", namestr, m_cheats[line + m_cheatlist_offset].definition.readable_name, toggle_str);
                    strcat(CheatsLabelsStr, "\n");
                    strcat(CheatsEnableStr, ss);
                } else {
                    snprintf(ss, sizeof ss, "%s%s %s\n", namestr, m_cheats[line + m_cheatlist_offset].definition.readable_name, toggle_str);
                    strcat(CheatsLabelsStr, ss);
                    if (m_show_only_enabled_cheats)
                        snprintf(ss, sizeof ss, "\n");
                    else
                        snprintf(ss, sizeof ss, "%s\n", (m_cheats[line + m_cheatlist_offset].enabled) ? "\u25A0" : "\u25A1");
                    strcat(CheatsEnableStr, ss);
                }
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
	uint64_t bookmarkEnableCheatCombo = MapButtons(strBookmarkEnableCheatCombo);
    uint64_t bookmarkPauseCheatCombo = MapButtons(strBookmarkPauseCheatCombo);
    uint64_t bookmarkIncreaseFontSizeCombo = MapButtons(strBookmarkIncreaseFontSizeCombo);
    uint64_t bookmarkDecreaseFontSizeCombo = MapButtons(strBookmarkDecreaseFontSizeCombo);

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
                                m_debugger->readMemory(&nextaddress, ((m_32bitmode) ? sizeof(u32) : sizeof(u64)), nextaddress);
                        else {
                            break;
                        }
                    }
                } else {
                    address = ((bookmark.heap) ? ((m_debugger->queryMemory(metadata.heap_extents.base).type == 0) ? metadata.alias_extents.base : metadata.heap_extents.base) : metadata.main_nso_extents.base) + bookmark.offset;
                }
                searchValue_t value = {0};
                m_debugger->readMemory(&value, dataTypeSizes[bookmark.type], address);
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
                    m_debugger->writeMemory(&(m_oldvalue[line]), dataTypeSizes[bookmark.type], address);
                }
                snprintf(ss, sizeof ss, "%s\n", _getAddressDisplayString(address, m_debugger, (searchType_t)bookmark.type).c_str());
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

        for (auto entry : m_toggle_list) {
            if (((keysHeld | keysDown) == entry.keycode) && (keysDown & entry.keycode)) {
                dmntchtToggleCheat(entry.cheat_id);
                refresh_cheats = true;
            }
        }
        if (isKeyComboPressed(keysHeld, keysDown, bookmarkEnableCheatCombo)) {
            m_cheatlist_offset = m_cheatlist_offset_save;
            TeslaFPS = 50;
            IsFrameBackground = false;
            tsl::hlp::requestForeground(true);
            FullMode = false;
            deactivateOriginalFooter = true;
            tsl::goBack();
            return true;
        }
        if (isKeyComboPressed(keysHeld, keysDown, bookmarkPauseCheatCombo)) {
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
        if (isKeyComboPressed(keysHeld, keysDown, bookmarkIncreaseFontSizeCombo)) {
            fontsize++;
            return true;
        }
        if (isKeyComboPressed(keysHeld, keysDown, bookmarkDecreaseFontSizeCombo)) {
            fontsize--;
            return true;
        }
        return false;
    }
};

//Main Menu
class MainMenu : public tsl::Gui {
private:
	uint64_t mainMenuChangeToBookmarkCombo = MapButtons(strMainMenuChangeToBookmarkCombo);
    uint64_t mainMenuIncreaseFontSizeCombo = MapButtons(strMainMenuIncreaseFontSizeCombo);
    uint64_t mainMenuDecreaseFontSizeCombo = MapButtons(strMainMenuDecreaseFontSizeCombo);
    uint64_t mainMenuOutlineModeSwitchesCombo = MapButtons(strMainMenuOutlineModeSwitchesCombo);
    uint64_t mainMenuSetBookmarkMultipier = MapButtons(strMainMenuSetBookmarkMultipier);
    uint64_t mainMenuNextLabel = MapButtons(strMainMenuNextLabel);
    uint64_t mainMenuPreviousLabel = MapButtons(strMainMenuPreviousLabel);
public:
    MainMenu() {}
    ~MainMenu() {
        refresh_cheats = false;
        if (m_cheats) {
            delete m_cheats;
            m_cheats = nullptr;
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
            auto NoCheats = new tsl::elm::ListItem("NoDmntMainMenuListItemText"_tr);
            list->addItem(NoCheats);
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

        if (m_cheatCnt == 0) {
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
                                m_debugger->readMemory(&nextaddress, ((m_32bitmode) ? sizeof(u32) : sizeof(u64)), nextaddress);
                        else {
                            break;
                        }
                    }
                } else {
                    address = ((bookmark.heap) ? ((m_debugger->queryMemory(metadata.heap_extents.base).type == 0) ? metadata.alias_extents.base : metadata.heap_extents.base) : metadata.main_nso_extents.base) + bookmark.offset;
                }
                searchValue_t value = {0};
                m_debugger->readMemory(&value, dataTypeSizes[bookmark.type], address);
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
                    m_debugger->writeMemory(&(m_oldvalue[line]), dataTypeSizes[bookmark.type], address);
                }
                snprintf(ss, sizeof ss, "%s\n", ((m_index == line) && m_edit_value) ? valueStr_edit_display(Display).c_str() : _getAddressDisplayString(address, m_debugger, (searchType_t)bookmark.type).c_str());
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
            strncat(Cursor, "UpdateEditCheatValueMainMenuCustomDrawerText"_tr.c_str(), sizeof Cursor - 1);
            strncat(MultiplierStr, "\n", sizeof MultiplierStr - 1);
            for (u8 i = 0; i < keyNames.size(); i++) {
                strncat(Cursor, (i == m_value_edit_index) ? "->\n" : "\n", sizeof Cursor - 1);
                strncat(MultiplierStr, (keyNames[i]+"\n").c_str(), sizeof MultiplierStr - 1);
            }
            return;
        }
        if (m_show_outline) {
            strncat(Cursor, "UpdateShowOutlineCursorMainMenuCustomDrawerText"_tr.c_str(), sizeof Cursor - 1);
            strncat(BookmarkLabels, "\n", sizeof BookmarkLabels - 1);
            strncat(MultiplierStr, "\n", sizeof MultiplierStr - 1);
            for (u8 i = 0; i < m_outline.size(); i++) {
                strncat(Cursor, (i == m_outline_index && !m_cursor_on_bookmark) ? "\uE019\n" : "\n", sizeof Cursor - 1);
                strncat(MultiplierStr, ("[" + m_outline[i].label + "]\n").c_str(), sizeof MultiplierStr - 1);
            }
            return;
        }
        if (m_AttributeDumpBookmark->size() == 0) m_cursor_on_bookmark = false;
        m_show_only_enabled_cheats = false;
        getcheats();
        strncat(BookmarkLabels, CheatsLabelsStr, sizeof BookmarkLabels - 1);
        strncat(Cursor, CheatsCursor, sizeof Cursor - 1);
        strncat(MultiplierStr, CheatsEnableStr, sizeof MultiplierStr - 1);
    }

    virtual bool handleInput(u64 keysDown, u64 keysHeld, const HidTouchState &touchPos, HidAnalogStickState leftJoyStick, HidAnalogStickState rightJoyStick) override {
        if (!dmnt_present || !m_debugger) {
            if (keysDown & HidNpadButton_B) {
                tsl::goBack();
            }
            return true;
        }

        dmntchtHasCheatProcess(&(m_debugger->m_dmnt));
        if (!m_debugger->m_dmnt) {
            if (keysDown & HidNpadButton_B) {
                tsl::goBack();
            }
            return true;
        }

<<<<<<< HEAD
		if (!m_cheatCnt) {
=======
        if (!m_cheatCnt) {
>>>>>>> d176a10 (add key combo configuration)
            if (keysDown & HidNpadButton_B) {
                tsl::goBack();
            }
            return true;
        }

        static u32 keycode;
        u32 redirect_index = m_cheat_index + m_cheatlist_offset;
        if (m_outline_mode) redirect_index = m_cheat_outline[redirect_index].index;
        for (auto entry : m_toggle_list) {
            if (((keysHeld | keysDown) == entry.keycode) && (keysDown & entry.keycode)) {
                dmntchtToggleCheat(entry.cheat_id);
                refresh_cheats = true;
            }
        }
        if (m_editCheat) {
            if (keysDown == 0) return false;
            keycode = keycode | keysDown;  // Waitforkey_menu will send keycode in index to this buttonid;
            keycount--;
            if (keycount > 0) return true;
            m_editCheat = false;
            if (m_get_toggle_keycode) {
                toggle_list_t entry;
                entry.cheat_id = m_cheats[redirect_index].cheat_id;
                entry.keycode = keycode;
                m_toggle_list.push_back(entry);
                m_get_toggle_keycode = false;
            } else if (m_get_action_keycode) {
                breeze_action_list_t entry;
                entry.index = m_index;
                entry.keycode = keycode;
                entry.breeze_action = Set;
                entry.freeze_value._u16 = 10;
                m_breeze_action_list.push_back(entry); // temp test code
                m_get_action_keycode = false;
            } else {
                if ((m_cheats[redirect_index].definition.opcodes[0] & 0xF0000000) == 0x80000000) {
                    m_cheats[redirect_index].definition.opcodes[0] = keycode;
                } else {
                    if (m_cheats[redirect_index].definition.num_opcodes < 0x100 + 2) {
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
                searchValue_t searchValue;
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
                m_debugger->writeMemory(&searchValue, dataTypeSizes[m_selected_type], m_selected_address);
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
        if (isKeyComboPressed(keysHeld, keysDown, mainMenuChangeToBookmarkCombo)) {
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
        }
        if (isKeyComboPressed(keysHeld, keysDown, mainMenuIncreaseFontSizeCombo)) { // font size++
            fontsize++;
            return true;
        }
        if (isKeyComboPressed(keysHeld, keysDown, mainMenuDecreaseFontSizeCombo)) { // font size--
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
        if (keysDown & HidNpadButton_X && !(isInKeyComboList(keysHeld, keysDown))) { // force switch to outline mode
            if (m_outline_mode) return true;
            if (m_outline.size() > 1) {
                m_showALlCheats = !m_showALlCheats;
                m_cheatlist_offset = m_outline[m_outline_index].index;
                m_cheat_index = 0;
            }
            return true;
        }
        if (isKeyComboPressed(keysHeld, keysDown, mainMenuOutlineModeSwitchesCombo)) { // switch to outline/non-outline mode
            m_outline_mode = !m_outline_mode;
            if (m_outline_mode) {
                m_showALlCheats = true;
                m_cheat_index = m_cheat_index_save;
                m_cheatlist_offset = m_cheatlist_offset_save;
            } else {
                m_cheat_index_save = m_cheat_index;
                m_cheatlist_offset_save = m_cheatlist_offset;
                m_cheat_index = 0;
                m_cheatlist_offset = redirect_index;
            }
            return true;
        }
        if (keysDown & HidNpadButton_Y) {  //find next enabled cheat
            m_show_outline = false;
            m_outline_mode = false;
            m_cursor_on_bookmark = false;
            m_showALlCheats = true;
            if ((m_cheat_index + m_cheatlist_offset) >= m_cheatCnt - 1) {
                m_cheat_index = 0;
                m_cheatlist_offset = 0;
                if (m_cheats[m_cheat_index + m_cheatlist_offset].enabled) return true;
            }
            do {
                if ((m_cheat_index < NUM_cheats - 1) && ((m_cheat_index + m_cheatlist_offset) < m_cheatCnt - 1))
                    m_cheat_index++;
                else if ((m_cheat_index + m_cheatlist_offset) < m_cheatCnt - 1)
                    m_cheatlist_offset++;
                else
                    break;
            } while (!m_cheats[m_cheat_index + m_cheatlist_offset].enabled);
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
                for (u8 i = 0; i < m_cheatCnt; i++) {
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
        if ((keysDown & HidNpadButton_A) && m_cursor_on_bookmark) { // remove cheat item
            valueStr = _getAddressDisplayString(m_selected_address, m_debugger, m_selected_type);
            value_pos = valueStr.length();
            m_edit_value = true;
            return true;
        }
        if ((keysDown & HidNpadButton_Plus) && !(isInKeyComboList(keysHeld, keysDown)) && !m_cursor_on_bookmark) { // add bookmark
            addbookmark();
            return true;
        }
        if ((keysDown & HidNpadButton_Minus) && m_cursor_on_bookmark) { // remove bookmark
            deletebookmark();
            if (((m_index >= NUM_bookmark) || ((m_index + m_addresslist_offset) >= (m_AttributeDumpBookmark->size() / sizeof(bookmark_t) ))) && m_index > 0) m_index--;
            return true;
        }
        if ((keysDown & HidNpadButton_Minus) && !m_cursor_on_bookmark && m_outline_mode) { // remove cheat
            auto outline_entry = m_cheat_outline[m_cheat_index + m_cheatlist_offset];
            if (outline_entry.is_outline && !outline_entry.always_expanded) {
                for (auto i = outline_entry.index; i <= outline_entry.index + outline_entry.size; i++)
                    dmntchtRemoveCheat(m_cheats[i].cheat_id);
            } else
                dmntchtRemoveCheat(m_cheats[outline_entry.index].cheat_id);
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
            return true;
        }
        if ((keysDown & HidNpadButton_Minus) && !m_cursor_on_bookmark && !m_outline_mode) { // remove cheat
            dmntchtRemoveCheat(m_cheats[redirect_index].cheat_id);
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
            u32 m_cheatlineCnt = (m_outline_mode) ? m_cheat_outline.size() : m_cheatCnt;
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
        if (isKeyComboPressed(keysHeld, keysDown, mainMenuSetBookmarkMultipier) && m_cursor_on_bookmark) { // set bookmark multipier
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
                auto entry = m_cheat_outline[index];
                if (entry.is_outline && !entry.always_expanded) {
                        if (!entry.expanded) {
                            for (u32 i = 1; i <= entry.size; i++) {
                                cheat_outline_entry_t new_entry = {};
                                new_entry.index = entry.index + i;
                                m_cheat_outline.insert(m_cheat_outline.begin() + index + i, new_entry);
                            }
                            entry.expanded = true;
                        } else {
                            m_cheat_outline.erase(m_cheat_outline.begin() + index + 1, m_cheat_outline.begin() + index + 1 + entry.size);
                            entry.expanded = false;
                        }
                        m_cheat_outline[index] = entry;
                        refresh_cheats = true;
                        return true;
                }
                index = entry.index;
            } else if (m_cheats[index].definition.opcodes[0] == 0x20000000) {
                if (m_outline.size() > 1)
                    m_show_outline = true;
                return true;
            }
            if (m_cheats[index].enabled)
                dmntchtToggleCheat(m_cheats[index].cheat_id);
            else {
                if (m_cheats[index].definition.num_opcodes + total_opcode <= MaximumProgramOpcodeCount)
                    dmntchtToggleCheat(m_cheats[index].cheat_id);
            }
            refresh_cheats = true;
            return true;
        }
        if (isKeyComboPressed(keysHeld, keysDown, mainMenuNextLabel)) {  // Next label
            if (m_outline_mode) {
                auto i = m_cheat_index + m_cheatlist_offset;
                while (i < m_cheat_outline.size()) {
                    i++;
                    if (m_cheat_outline[i].is_outline) {
                        m_cheatlist_offset = i - m_cheat_index;
                        break;
                    }
                }
            }
            return true;
        }
        if (isKeyComboPressed(keysHeld, keysDown, mainMenuPreviousLabel)) {  // Previous label
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
                "UpdateCursorOnBookmarkMainMenuCustomDrawerText": "%s v%s\nPID: %03ld TID: %016lX BID: %02X%02X%02X%02X%02X%02X%02X%02X\n\uE092\uE093\uE091\uE090 nav\n\uE0A4 \uE0A5 Change  \uE0A0 Edit  \uE0A1 Exit  \uE0A6+\uE0A4/\uE0A5 Font size  \uE0B4 Deletet\n\uE0A6+\uE04E Toggle show all cheats  \uE0A3 Find next enabled cheat\n",
                "UpdateCursorNotOnBookmarkMainMenuCustomDrawerText": "%s v%s\nPID: %03ld TID: %016lX BID: %02X%02X%02X%02X%02X%02X%02X%02X\n\uE092\uE093\uE091\uE090\uE0A4\uE0A5 nav\n\uE0A0 Toggle  \uE0B3 Add bookmark  \uE0B4 Delete bookmark  \uE0A1 Exit\n\n",
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
