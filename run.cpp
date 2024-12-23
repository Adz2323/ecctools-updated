#include <iostream>
#include <string>
#include <memory>
#include <array>
#include <regex>
#include <thread>
#include <chrono>
#include <sstream>

std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    
    return result;
}

std::string runKeydivision(std::string& linePrivKey) {
    std::string cmd = "./Auto -f scanned_pubkeys.bin -b 160 -t 2 "
                     "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16 "
                     "02e0a8b039282faf6fe0fd769cfbc4b6b4cf8758ba68220eac420e32b91ddfa673 "
                     "035cd1854cae45391ca4ec428cc7e6c7d9984424b954209a8eea197b9e364c05f6 "
                     "03137807790ea7dc6e97901c2bc87411f45ed74a5629315c4e4b03a0a102250c49 "
                     "03afdda497369e219a2c1c369954a930e4d3740968e5e4352475bcffce3140dae5 "
                     "03afdda497369e219a2c1c369954a930e4d3740968e5e4352475bcffce3140dae5 "
                     "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640";
    
    std::cout << "Running keydivision..." << std::endl;
    std::string output = exec(cmd.c_str());
    
    // Regular expressions to find both private keys
    std::regex linePrivKeyRegex("Line Number Private Key \\(Hex\\): ([a-fA-F0-9]+)");
    std::regex origPrivKeyRegex("Original Private Key: ([a-fA-F0-9]+)");
    std::smatch match;
    
    // Store the line number private key
    if (std::regex_search(output, match, linePrivKeyRegex)) {
        linePrivKey = match[1].str();
    }
    
    // Find and return the original private key
    if (std::regex_search(output, match, origPrivKeyRegex)) {
        std::string origPrivKey = match[1].str();
        std::cout << "Found original private key: " << origPrivKey << std::endl;
        return origPrivKey;
    }
    
    return "";
}

void runElectrum(const std::string& privateKey) {
    // Start electrum process
    FILE* electrum = popen("./electrum", "w");
    if (!electrum) {
        std::cerr << "Failed to start Electrum" << std::endl;
        return;
    }
    
    // Wait a moment for Electrum to initialize
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    // Write the original private key to Electrum's stdin
    fprintf(electrum, "%s\n", privateKey.c_str());
    fflush(electrum);
    
    // Close the pipe
    pclose(electrum);
}

int main() {
    std::string linePrivKey;
    std::string origPrivKey = runKeydivision(linePrivKey);
    
    if (!origPrivKey.empty()) {
        std::cout << "Successfully found private keys:" << std::endl;
        std::cout << "Line Number Private Key: " << linePrivKey << std::endl;
        std::cout << "Original Private Key: " << origPrivKey << std::endl;
        std::cout << "Starting Electrum with original private key..." << std::endl;
        runElectrum(origPrivKey);
    } else {
        std::cout << "No private key found in keydivision output." << std::endl;
        return 1;
    }
    
    return 0;
}
