
#pragma once
#define ALWAYS_INLINE inline __attribute__((always_inline))

#include <switch.h>
#include <map>
#include <string>
#include <vector>
#include <numeric>
#include <algorithm>
#include <cstdint>
#include <sys/stat.h>

using IniData = std::map<std::string, std::map<std::string, std::string>>;

// default key combo
// NOTE: these are defined at namespace scope in a header. Marking them
// `inline` (C++17 inline variables) keeps a single definition across all
// translation units that include this header, avoiding ODR violations.
inline std::string strBookmarkEnableCheatCombo = "LSTICK+RSTICK";
inline std::string strBookmarkPauseCheatCombo = "Y+ZL";
inline std::string strBookmarkIncreaseFontSizeCombo = "R+ZL";
inline std::string strBookmarkDecreaseFontSizeCombo = "L+ZL";

inline std::string strMainMenuChangeToBookmarkCombo = "Y+ZL";
inline std::string strMainMenuIncreaseFontSizeCombo = "R+ZL";
inline std::string strMainMenuDecreaseFontSizeCombo = "L+ZL";
inline std::string strMainMenuOutlineModeSwitchesCombo = "X+ZL";
inline std::string strMainMenuSetBookmarkMultipier = "L+R";
inline std::string strMainMenuNextLabel = "R+ZR";
inline std::string strMainMenuPreviousLabel = "L+ZR";

inline std::vector<std::string> split(const std::string& str, char delim = ' ') {
    std::vector<std::string> out;
    std::size_t current, previous = 0;
    current = str.find(delim);
    while (current != std::string::npos) {
        out.push_back(str.substr(previous, current - previous));
        previous = current + 1;
        current = str.find(delim, previous);
    }
    out.push_back(str.substr(previous, current - previous));
    return out;
}

inline IniData parseIni(const std::string &str) {
    IniData iniData;
    auto lines = split(str, '\n');
    std::string lastHeader = "";
    for (auto& line : lines) {
        line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());

        // After whitespace stripping a blank/comment line can be empty;
        // indexing line[0]/line[size-1] on an empty string is UB, so skip.
        if (line.empty()) {
            continue;
        }
        if (line[0] == '[' && line[line.size() - 1] == ']') {
            lastHeader = line.substr(1, line.size() - 2);
            iniData.emplace(lastHeader, std::map<std::string, std::string>{});
        }
        else if (auto keyValuePair = split(line, '='); keyValuePair.size() == 2) {
            iniData[lastHeader].emplace(keyValuePair[0], keyValuePair[1]);
        }
    }
    return iniData;
}

// String formatting functions
inline void removeSpaces(std::string& str) {
	str.erase(std::remove(str.begin(), str.end(), ' '), str.end());
}

inline void convertToUpper(std::string& str) {
	std::transform(str.begin(), str.end(), str.begin(), ::toupper);
}

inline void convertToLower(std::string& str) {
	std::transform(str.begin(), str.end(), str.begin(), ::tolower);
}

inline void formatButtonCombination(std::string& line) {
	std::map<std::string, std::string> replaces{
		{"A", "\uE0E0"},
		{"B", "\uE0E1"},
		{"X", "\uE0E2"},
		{"Y", "\uE0E3"},
		{"L", "\uE0E4"},
		{"R", "\uE0E5"},
		{"ZL", "\uE0E6"},
		{"ZR", "\uE0E7"},
		{"SL", "\uE0E8"},
		{"SR", "\uE0E9"},
		{"DUP", "\uE0EB"},
		{"DDOWN", "\uE0EC"},
		{"DLEFT", "\uE0ED"},
		{"DRIGHT", "\uE0EE"},
		{"PLUS", "\uE0EF"},
		{"MINUS", "\uE0F0"},
		{"LSTICK", "\uE104"},
		{"RSTICK", "\uE105"},
		{"RS", "\uE105"},
		{"LS", "\uE104"}
	};
	// Remove all spaces from the line
	line.erase(std::remove(line.begin(), line.end(), ' '), line.end());

	// Replace '+' with ' + '
	size_t pos = 0;
	size_t max_pluses = 3;
	while ((pos = line.find('+', pos)) != std::string::npos) {
		if (!max_pluses) {
			line = line.substr(0, pos);
			return;
		}
		if (pos > 0 && pos < line.size() - 1) {
			if (std::isalnum(line[pos - 1]) && std::isalnum(line[pos + 1])) {
				line.replace(pos, 1, " + ");
				pos += 3;
			}
		}
		++pos;
		max_pluses--;
	}
	pos = 0;
	size_t old_pos = 0;
	while ((pos = line.find(" + ", pos)) != std::string::npos) {

		std::string button = line.substr(old_pos, pos - old_pos);
		if (replaces.find(button) != replaces.end()) {
			line.replace(old_pos, button.length(), replaces[button]);
			pos = 0;
			old_pos = 0;
		}
		else pos += 3;
		old_pos = pos;
	}
	std::string button = line.substr(old_pos);
	if (replaces.find(button) != replaces.end()) {
		line.replace(old_pos, button.length(), replaces[button]);
	}	
}

inline uint64_t MapButtons(const std::string& buttonCombo) {
	// static const so the lookup table is built exactly once per process
	// instead of on every call. MapButtons is invoked from the per-frame
	// input hot path, and previously each call heap-allocated a 24-entry
	// std::map.
	static const std::map<std::string, uint64_t> buttonMap = {
		{"A", HidNpadButton_A},
		{"B", HidNpadButton_B},
		{"X", HidNpadButton_X},
		{"Y", HidNpadButton_Y},
		{"L", HidNpadButton_L},
		{"R", HidNpadButton_R},
		{"ZL", HidNpadButton_ZL},
		{"ZR", HidNpadButton_ZR},
		{"PLUS", HidNpadButton_Plus},
		{"MINUS", HidNpadButton_Minus},
		{"DUP", HidNpadButton_Up},
		{"DDOWN", HidNpadButton_Down},
		{"DLEFT", HidNpadButton_Left},
		{"DRIGHT", HidNpadButton_Right},
		{"SL", HidNpadButton_AnySL},
		{"SR", HidNpadButton_AnySR},
		{"LSTICK", HidNpadButton_StickL},
		{"RSTICK", HidNpadButton_StickR},
		{"LS", HidNpadButton_StickL},
		{"RS", HidNpadButton_StickR},
		{"UP", HidNpadButton_AnyUp},
		{"DOWN", HidNpadButton_AnyDown},
		{"LEFT", HidNpadButton_AnyLeft},
		{"RIGHT", HidNpadButton_AnyRight}
	};

	uint64_t comboBitmask = 0;
	std::string comboCopy = buttonCombo;  // Make a copy of buttonCombo

	std::string delimiter = "+";
	size_t pos = 0;
	std::string button;
	size_t max_delimiters = 4;
	while ((pos = comboCopy.find(delimiter)) != std::string::npos) {
		button = comboCopy.substr(0, pos);
		if (auto it = buttonMap.find(button); it != buttonMap.end()) {
			comboBitmask |= it->second;
		}
		comboCopy.erase(0, pos + delimiter.length());
		if (!--max_delimiters) {
			return comboBitmask;
		}
	}
	if (auto it = buttonMap.find(comboCopy); it != buttonMap.end()) {
		comboBitmask |= it->second;
	}
	return comboBitmask;
}

// Pre-parsed key-combo bitmasks. MapButtons() walks a std::map for every
// token, and the overlay input code used to call it on every frame for every
// combo. These caches are recomputed only when the combo strings change (once,
// at the end of ParseIniFile), turning the per-frame hot path into pure
// integer bitmask compares.
inline uint64_t g_bookmarkEnableCheatCombo = 0;
inline uint64_t g_bookmarkPauseCheatCombo = 0;
inline uint64_t g_bookmarkIncreaseFontSizeCombo = 0;
inline uint64_t g_bookmarkDecreaseFontSizeCombo = 0;
inline uint64_t g_mainMenuChangeToBookmarkCombo = 0;
inline uint64_t g_mainMenuIncreaseFontSizeCombo = 0;
inline uint64_t g_mainMenuDecreaseFontSizeCombo = 0;
inline uint64_t g_mainMenuOutlineModeSwitchesCombo = 0;
inline uint64_t g_mainMenuSetBookmarkMultipier = 0;
inline uint64_t g_mainMenuNextLabel = 0;
inline uint64_t g_mainMenuPreviousLabel = 0;

inline void RefreshKeyComboMasks() {
	g_bookmarkEnableCheatCombo        = MapButtons(strBookmarkEnableCheatCombo);
	g_bookmarkPauseCheatCombo         = MapButtons(strBookmarkPauseCheatCombo);
	g_bookmarkIncreaseFontSizeCombo   = MapButtons(strBookmarkIncreaseFontSizeCombo);
	g_bookmarkDecreaseFontSizeCombo   = MapButtons(strBookmarkDecreaseFontSizeCombo);
	g_mainMenuChangeToBookmarkCombo   = MapButtons(strMainMenuChangeToBookmarkCombo);
	g_mainMenuIncreaseFontSizeCombo   = MapButtons(strMainMenuIncreaseFontSizeCombo);
	g_mainMenuDecreaseFontSizeCombo   = MapButtons(strMainMenuDecreaseFontSizeCombo);
	g_mainMenuOutlineModeSwitchesCombo = MapButtons(strMainMenuOutlineModeSwitchesCombo);
	g_mainMenuSetBookmarkMultipier    = MapButtons(strMainMenuSetBookmarkMultipier);
	g_mainMenuNextLabel               = MapButtons(strMainMenuNextLabel);
	g_mainMenuPreviousLabel           = MapButtons(strMainMenuPreviousLabel);
}

/**
 * @brief 判断组合键是否处于“当前所有按键都按下”的状态（覆盖所有场景）
 * 
 * @param keysDown 当前帧新按下的按键（位掩码）
 * @param keysHeld 已持续按住超过1帧的按键（位掩码）
 * @param comboBitmask 目标组合键（如 KEY_A | KEY_B | KEY_L）
 * @return true 组合键所有按键当前都按下（无论新按还是持续按）；false 未满足
 */
ALWAYS_INLINE bool isKeyComboPressed(u64 keysDown, u64 keysHeld, u64 comboBitmask) {
	return (((keysDown | keysHeld) & comboBitmask) == comboBitmask) &&
		!((keysDown | keysHeld) & ~comboBitmask);
}

/**
 * @brief 边沿触发版组合键判定：仅当组合键中至少有一个键“本帧新按下”时返回一次 true。
 * isKeyComboPressed 是电平触发（只要还按着就每帧为真），对于 changeTo/goBack/模式
 * 切换/字号/倍率这类一次性动作会导致按住时每帧重复触发（在两个 overlay 间反复横跳）。
 * 参数顺序沿用调用点习惯：keysHeld 在前，keysDown（本帧新按下）在后。
 *
 * @param keysHeld 已持续按住超过1帧的按键（位掩码）
 * @param keysDown 当前帧新按下的按键（位掩码）
 * @param comboBitmask 目标组合键
 * @return true 组合键完整且本帧有新按下的成员键；false 未满足或仅处于按住状态
 */
ALWAYS_INLINE bool isKeyComboJustPressed(u64 keysHeld, u64 keysDown, u64 comboBitmask) {
	return isKeyComboPressed(keysHeld, keysDown, comboBitmask) &&
		(keysDown & comboBitmask);
}

/**
 * @brief 检查在已知keysDown包含部分组合键的情况下，keysHeld是否包含剩余必要按键
 * 
 * @param keysDown 当前帧新按下的键（已知包含组合键中的部分按键）
 * @param keysHeld 已持续按住超过1帧的键
 * @return true 组合键的所有按键要么在keysDown中，要么在keysHeld中（组合完整）；false 不完整
 */
inline bool isInKeyComboList(const u64 keysDown, const u64 keysHeld) {
    // Use the pre-parsed masks instead of calling MapButtons() 14 times per
    // invocation. The masks are refreshed once at startup (ParseIniFile) and
    // only change if the combo strings are reloaded.
    const u64 notDown = ~keysDown;
    uint64_t m;
    m = g_mainMenuChangeToBookmarkCombo & notDown;  if ((keysHeld & m) == m) return true;
    m = g_mainMenuIncreaseFontSizeCombo & notDown;  if ((keysHeld & m) == m) return true;
    m = g_mainMenuDecreaseFontSizeCombo & notDown;  if ((keysHeld & m) == m) return true;
    m = g_mainMenuOutlineModeSwitchesCombo & notDown; if ((keysHeld & m) == m) return true;
    m = g_mainMenuSetBookmarkMultipier & notDown;   if ((keysHeld & m) == m) return true;
    m = g_mainMenuNextLabel & notDown;              if ((keysHeld & m) == m) return true;
    m = g_mainMenuPreviousLabel & notDown;          if ((keysHeld & m) == m) return true;
    return false;
}

inline void ParseIniFile() {
	std::string overlayName;
	std::string directoryPath = "sdmc:/config/" APPTITLE "/";
	std::string configIniPath = directoryPath + "keycombo.ini";
	IniData parsedData;

	struct stat st;
	if (stat(directoryPath.c_str(), &st) != 0) {
		mkdir(directoryPath.c_str(), 0777);
	}

	// Open the INI file
	FILE* configFileIn = fopen(configIniPath.c_str(), "r");
	if (configFileIn) {
		// Determine the size of the INI file
		fseek(configFileIn, 0, SEEK_END);
		long fileSize = ftell(configFileIn);
		rewind(configFileIn);

		// Parse the INI data
		std::string fileDataString(fileSize, '\0');
		fread(&fileDataString[0], sizeof(char), fileSize, configFileIn);
		fclose(configFileIn);

		parsedData = parseIni(fileDataString);
		if (parsedData.find("key_combo") != parsedData.end()) {
			if (parsedData["key_combo"].find("bookmarkEnableCheatCombo") != parsedData["key_combo"].end()) {
				strBookmarkEnableCheatCombo = parsedData["key_combo"]["bookmarkEnableCheatCombo"];
				removeSpaces(strBookmarkEnableCheatCombo);
				convertToUpper(strBookmarkEnableCheatCombo);
			}
			if (parsedData["key_combo"].find("bookmarkPauseCheatCombo") != parsedData["key_combo"].end()) {
				strBookmarkPauseCheatCombo = parsedData["key_combo"]["bookmarkPauseCheatCombo"];
				removeSpaces(strBookmarkPauseCheatCombo);
				convertToUpper(strBookmarkPauseCheatCombo);
			}
			if (parsedData["key_combo"].find("bookmarkIncreaseFontSizeCombo") != parsedData["key_combo"].end()) {
				strBookmarkIncreaseFontSizeCombo = parsedData["key_combo"]["bookmarkIncreaseFontSizeCombo"];
				removeSpaces(strBookmarkIncreaseFontSizeCombo);
				convertToUpper(strBookmarkIncreaseFontSizeCombo);
			}
			if (parsedData["key_combo"].find("bookmarkDecreaseFontSizeCombo") != parsedData["key_combo"].end()) {
				strBookmarkDecreaseFontSizeCombo = parsedData["key_combo"]["bookmarkDecreaseFontSizeCombo"];
				removeSpaces(strBookmarkDecreaseFontSizeCombo);
				convertToUpper(strBookmarkDecreaseFontSizeCombo);
			}
			if (parsedData["key_combo"].find("mainMenuChangeToBookmarkCombo") != parsedData["key_combo"].end()) {
				strMainMenuChangeToBookmarkCombo = parsedData["key_combo"]["mainMenuChangeToBookmarkCombo"];
				removeSpaces(strMainMenuChangeToBookmarkCombo);
				convertToUpper(strMainMenuChangeToBookmarkCombo);
			}
			if (parsedData["key_combo"].find("mainMenuIncreaseFontSizeCombo") != parsedData["key_combo"].end()) {
				strMainMenuIncreaseFontSizeCombo = parsedData["key_combo"]["mainMenuIncreaseFontSizeCombo"];
				removeSpaces(strMainMenuIncreaseFontSizeCombo);
				convertToUpper(strMainMenuIncreaseFontSizeCombo);
			}
			if (parsedData["key_combo"].find("mainMenuDecreaseFontSizeCombo") != parsedData["key_combo"].end()) {
				strMainMenuDecreaseFontSizeCombo = parsedData["key_combo"]["mainMenuDecreaseFontSizeCombo"];
				removeSpaces(strMainMenuDecreaseFontSizeCombo);
				convertToUpper(strMainMenuDecreaseFontSizeCombo);
			}
			if (parsedData["key_combo"].find("mainMenuOutlineModeSwitchesCombo") != parsedData["key_combo"].end()) {
				strMainMenuOutlineModeSwitchesCombo = parsedData["key_combo"]["mainMenuOutlineModeSwitchesCombo"];
				removeSpaces(strMainMenuOutlineModeSwitchesCombo);
				convertToUpper(strMainMenuOutlineModeSwitchesCombo);
			}
			if (parsedData["key_combo"].find("mainMenuSetBookmarkMultipier") != parsedData["key_combo"].end()) {
				strMainMenuSetBookmarkMultipier = parsedData["key_combo"]["mainMenuSetBookmarkMultipier"];
				removeSpaces(strMainMenuSetBookmarkMultipier);
				convertToUpper(strMainMenuSetBookmarkMultipier);
			}
			if (parsedData["key_combo"].find("mainMenuNextLabel") != parsedData["key_combo"].end()) {
				strMainMenuNextLabel = parsedData["key_combo"]["mainMenuNextLabel"];
				removeSpaces(strMainMenuNextLabel);
				convertToUpper(strMainMenuNextLabel);
			}
			if (parsedData["key_combo"].find("mainMenuPreviousLabel") != parsedData["key_combo"].end()) {
				strMainMenuPreviousLabel = parsedData["key_combo"]["mainMenuPreviousLabel"];
				removeSpaces(strMainMenuPreviousLabel);
				convertToUpper(strMainMenuPreviousLabel);
			}
		}
	}

	// Recompute the cached bitmasks from the (possibly default) combo strings.
	// Always runs, even when keycombo.ini is absent, so the masks reflect the
	// built-in defaults.
	RefreshKeyComboMasks();
}
