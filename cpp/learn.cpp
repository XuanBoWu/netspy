#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm> // for std::find
#include <unistd.h> // for usleep

std::vector<std::string> readUdpFile() {
    std::ifstream udpFile("/proc/net/udp");
    std::vector<std::string> lines;
    std::string line;

    if (udpFile.is_open()) {
        while (std::getline(udpFile, line)) {
            lines.push_back(line);
        }
        udpFile.close();
    } else {
        std::cerr << "Unable to open /proc/net/udp" << std::endl;
    }

    return lines;
}

void compareAndSaveChanges(const std::vector<std::string>& oldLines, const std::vector<std::string>& newLines) {
    // 检查新增的行
    for (const auto& newLine : newLines) {
        if (std::find(oldLines.begin(), oldLines.end(), newLine) == oldLines.end()) {
            std::cout << "New line: " << newLine << std::endl;
        }
    }

    // 检查删除的行
    for (const auto& oldLine : oldLines) {
        if (std::find(newLines.begin(), newLines.end(), oldLine) == newLines.end()) {
            std::cout << "Deleted line: " << oldLine << std::endl;
        }
    }
}

int main() {
    std::vector<std::string> oldLines = readUdpFile();

    while (true) {
        usleep(10); // 等待10毫秒
        std::vector<std::string> newLines = readUdpFile();

        compareAndSaveChanges(oldLines, newLines);

        oldLines = newLines; // 更新旧数据
    }

    return 0;
}
