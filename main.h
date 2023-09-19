#ifndef MY_PROJECT_H
#define MY_PROJECT_H

#include <string>
#include <vector>
#include <unordered_set>

// Anti-analysis techniques
bool isDebuggerPresent();
bool isDebuggerAttachedThroughProcessEnum();
bool isDebuggerAttachedThroughTiming();

// Encryption and Decryption
std::string loadDecryptionKey();
std::string decryptLine(const std::string& encryptedLine, const std::string& key);

// Assembly obfuscation
bool isLongInstruction(const std::string& instruction);
std::string replaceWithBlockCall(const std::string& instruction, const std::string& label);
std::string createDeobfuscationBlock(const std::string& label, const std::string& instruction);
std::vector<std::string> splitFunction(const std::vector<std::string>& lines);

// Constant obfuscation
std::string obfuscateConstants(const std::string& line);

// Windows internals
// Include Windows-specific headers and declare functions related to Windows internals here

// Fake UPX detection
bool isFakeUPX(const std::string& fileName);

// Complex junk partition addition
std::vector<std::string> addJunkPartitionsComplex(const std::vector<std::string>& lines);

// Bytecode obfuscation
std::string bytecodeObfuscation(const std::string& line);

#endif // MY_PROJECT_H
