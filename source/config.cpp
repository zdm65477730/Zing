#include "config.hpp"
#include <sys/stat.h>

static Config::config_data_t configData = {};

void Config::readConfig() {
    configData = {};
    mkdir("/switch", 0777);
    mkdir(EDIZON_DIR "", 0777);
    snprintf(configData.edizon_dir, sizeof configData.edizon_dir, EDIZON_DIR);
    if (access(CONFIG_PATH, F_OK) == 0) {
        FILE *configFile = fopen(CONFIG_PATH, "r+");
        fread(&configData, 1, sizeof(config_data_t), configFile);
        fclose(configFile);

        if (strcmp(configData.magic, "EDZOCFG") != 0) {
        configData = {};
        Config::writeConfig();
        }
    } else
        Config::writeConfig();
}

void Config::writeConfig() {
    FILE *configFile = fopen(CONFIG_PATH, "wr");

    memcpy(configData.magic, "EDZOCFG", 8);
    fwrite(&configData, 1, sizeof(config_data_t), configFile);

    fclose(configFile);
}

Config::config_data_t* Config::getConfig() {
    return &configData;
}