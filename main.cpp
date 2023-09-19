#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdlib>
#include <ctime>
#include <unordered_set>
#include <windows.h>
#include <TlHelp32.h>
#include <regex>
#include <mutex>
#include <main.h>

std::mutex mtx; // Mutex for thread safety
// Function to generate random obfuscators
std::string generateObfuscator() {
    static const std::string obfuscators[] = {
        "\xB0",  // MOV AL, <imm8>
        "\xB4",  // MOV AH, <imm8>
        "\x0C",  // OR AL, <imm8>
        "\x24"   // AND AL, <imm8>
        // Add more obfuscators here
    };
    int index = rand() % (sizeof(obfuscators) / sizeof(obfuscators[0]));
    return obfuscators[index];
}

// Function to generate a random label
std::string generateRandomLabel() {
    static const char alphanum[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string label = "L";
    for (int i = 0; i < 5; ++i) {
        label += alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    return label;
}

// Function to check for the presence of a debugger
bool isDebuggerPresent() {
    return IsDebuggerPresent();
}

// Function to check for debugger through process enumeration
bool isDebuggerAttachedThroughProcessEnum() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &entry)) {
        do {
            if (wcsstr(entry.szExeFile, L"ollydbg") != NULL ||
                wcsstr(entry.szExeFile, L"idaq") != NULL ||
                wcsstr(entry.szExeFile, L"windbg") != NULL) {
                CloseHandle(snapshot);
                return true;
            }
        } while (Process32Next(snapshot, &entry));
    }
    
    CloseHandle(snapshot);
    return false;
}

// Function to check for debugger through timing analysis
bool isDebuggerAttachedThroughTiming() {
    LARGE_INTEGER frequency;
    QueryPerformanceFrequency(&frequency);

    LARGE_INTEGER start, end;
    QueryPerformanceCounter(&start);

    // Insert a delay for a known amount of time
    // The debugger will significantly slow this down
    Sleep(2000); // 2 seconds

    QueryPerformanceCounter(&end);

    long long elapsedMicroseconds = (end.QuadPart - start.QuadPart) * 1000000LL / frequency.QuadPart;
    
    return elapsedMicroseconds > 2500000; // If it took more than 2.5 seconds, likely under analysis
}

// Function to load a secret decryption key
std::string loadDecryptionKey() {
    // Implement code to load the decryption key from a secure location
    // This key should be kept secret and protected
}

// Function to decrypt a line of code
std::string decryptLine(const std::string& encryptedLine, const std::string& key) {
    // Implement code to decrypt the line using the decryption key
    // This process should use a strong encryption algorithm
}

// Function to decompress a line of code
std::string decompressLine(const std::string& compressedLine) {
    // Implement code to decompress the line using a compression algorithm
}

// Function to generate random garbage instructions
std::string generateGarbageInstruction() {
    static const std::string garbageInstructions[] = {
        "\x90",       // NOP (No Operation)
        "\x66\x90",   // NOP (16-bit)
        "\x0F\x1F\x00" // NOP (Multi-byte)
        // Add more garbage instructions here
    };
    int index = rand() % (sizeof(garbageInstructions) / sizeof(garbageInstructions[0]));
    return garbageInstructions[index];
}

// Function to obfuscate constants
char generateXORKey() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<char> dis(1, 255);
    return dis(gen);
}

// Function to obfuscate constants using XOR with a random key
std::string obfuscateConstants(const std::string& line) {
    std::string obfuscatedLine = line;
    char xorKey = generateXORKey();

    for (char& character : obfuscatedLine) {
        // XOR each character with the key to obfuscate constants
        character ^= xorKey;
    }

    return obfuscatedLine;
}

// Function to rename variables
std::string renameVariables(const std::string& line) {
    // Implement code to rename variables in the line
    // Keep track of variable mappings to maintain consistency
}

// Function to split functions
std::vector<std::string> splitFunction(const std::vector<std::string>& lines) {
    std::vector<std::string> splittedLines;

    // Initialize variables to keep track of the current function
    bool inFunction = false;
    std::vector<std::string> currentFunction;

    // Iterate through the lines of code
    for (const std::string& line : lines) {
        if (line.find(':') != std::string::npos) {
            // If a label is found, it might indicate the beginning of a new function
            if (inFunction) {
                // If we were already in a function, finish the current one
                currentFunction.push_back(line);
                splittedLines.insert(splittedLines.end(), currentFunction.begin(), currentFunction.end());
                currentFunction.clear();
            }
            // Start a new function
            inFunction = true;
            currentFunction.push_back(line);
        } else if (inFunction) {
            // If we are inside a function, add the line to the current function
            currentFunction.push_back(line);
        } else {
            // If we are not inside a function, add the line directly to the result
            splittedLines.push_back(line);
        }
    }

    // If there is an unfinished function, add it to the result
    if (!currentFunction.empty()) {
        splittedLines.insert(splittedLines.end(), currentFunction.begin(), currentFunction.end());
    }

    return splittedLines;
}

// Function to detect the architecture of the assembly file
bool detectArchitecture(const std::vector<std::string>& lines) {
    // Regular expression pattern to match x86-64 registers
    std::regex x86_64RegisterPattern(R"(\b(?:RAX|RSP|RBP|RIP|RBX|RCX|RDX|RDI|RSI|R8|R9|R10|R11|R12|R13|R14|R15)\b)");

    for (const std::string& line : lines) {
        if (std::regex_search(line, x86_64RegisterPattern)) {
            return true; // x86-64 detected
        }
    }

    // If no x86-64 registers were found, assume it's not x86-64
    return false;
}
// Function to create a de-obfuscation block
std::string createDeobfuscationBlock(const std::string& label, const std::string& instruction) {
    std::string blockCode;

    // Generate the de-obfuscation block code
    blockCode += label + ":\n";

    // Implement code to decode the instruction (e.g., using XOR, bit manipulation, etc.)
    // The decoding logic should match the obfuscation applied to the instruction

    // Implement code to write the decoded instruction to the memory
    // You may need to allocate memory for the decoded instruction

    // Implement code to execute the decoded instruction
    // Depending on the architecture, this may involve function pointers or direct execution

    // Implement code to clear any traces of the decoded instruction from memory

    return blockCode;
}

// Function to replace long instructions with a call to the appropriate block
std::string replaceWithBlockCall(const std::string& instruction, const std::string& label) {
    // You can customize the calling convention and stack management here
    // For demonstration purposes, we use the cdecl calling convention
    // This assumes that the de-obfuscation block takes no arguments

    std::string blockCall = "call " + label;  // Call the de-obfuscation block

    // Adjust the stack if necessary (e.g., if the original instruction used stack space)
    // Add code here to manage the stack if needed

    return blockCall;
}

// Function to check if an instruction is long
bool isLongInstruction(const std::string& instruction) {
    // x86-64 long instructions often have a length greater than 15 bytes
    // You can customize this threshold as needed
    const size_t longInstructionThreshold = 15;

    // Remove whitespace and comment characters for a more accurate length check
    std::string cleanInstruction = instruction;
    cleanInstruction.erase(std::remove_if(cleanInstruction.begin(), cleanInstruction.end(), ::isspace), cleanInstruction.end());
    size_t instructionLength = cleanInstruction.length();

    return instructionLength > longInstructionThreshold;
}
// Function to generate a random control flow structure
std::string generateRandomControlFlow() {
    static const std::string controlFlowInstructions[] = {
        "jmp $+5",        // Unconditional jump
        "jz $+5",         // Jump if zero flag is set
        "jnz $+5",        // Jump if zero flag is not set
        "je $+5",         // Jump if equal
        "jne $+5",        // Jump if not equal
        "js $+5",         // Jump if sign flag is set
        "jns $+5",        // Jump if sign flag is not set
        "call $+5",       // Call instruction
        "ret"             // Return instruction
        // Add more control flow instructions here
    };
    int index = rand() % (sizeof(controlFlowInstructions) / sizeof(controlFlowInstructions[0]));
    return controlFlowInstructions[index];
}

// Function to add junk partitions with control flow structures
std::vector<std::string> addJunkPartitionsComplex(const std::vector<std::string>& inputLines) {
    std::vector<std::string> outputLines;
    srand(static_cast<unsigned>(time(nullptr)));

    for (size_t i = 0; i < inputLines.size(); ++i) {
        outputLines.push_back(inputLines[i]);

        // Insert a junk partition with control flow structures randomly
        if (rand() % 100 < 10) { // 10% chance of inserting a junk partition
            int partitionSize = rand() % 20 + 10; // Randomly choose the size of the junk partition (between 10 and 29 lines)
            for (int j = 0; j < partitionSize; ++j) {
                std::string controlFlowInstruction = generateRandomControlFlow();
                outputLines.push_back(controlFlowInstruction);
            }
        }
    }

    return outputLines;
}

bool isFakeUPX(const std::string& fileName) {
    // Open the PE file
    std::ifstream file(fileName, std::ios::binary);
    if (!file) {
        return false; // Unable to open the file
    }

    // Check for the UPX signature in the PE header
    constexpr int upxSignatureLength = 2;
    char upxSignature[upxSignatureLength] = {'U', 'P'};
    char buffer[upxSignatureLength];

    file.seekg(0x3C, std::ios::beg); // Offset to the PE header offset
    uint32_t peHeaderOffset;
    file.read(reinterpret_cast<char*>(&peHeaderOffset), sizeof(peHeaderOffset));

    file.seekg(peHeaderOffset, std::ios::beg);
    file.read(buffer, upxSignatureLength);

    return memcmp(buffer, upxSignature, upxSignatureLength) == 0;
}
// Function to generate a random number within a range
int getRandomNumber(int min, int max) {
    return min + (rand() % (max - min + 1));
}

// Function to generate a random register (e.g., EAX, EBX, ECX)
std::string getRandomRegister() {
    static const std::string registers[] = {
        "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP"
    };
    int index = rand() % (sizeof(registers) / sizeof(registers[0]));
    return registers[index];
}

// Function to mutate an assembly instruction
std::string mutateInstruction(const std::string& instruction) {
    // Implement more sophisticated mutation logic here
    // For example, you can modify registers, opcodes, or operands
    std::string mutatedInstruction = instruction;

    // Randomly choose a mutation type
    int mutationType = getRandomNumber(0, 2);

    if (mutationType == 0) {
        // Mutate a register
        std::string originalRegister = getRandomRegister();
        std::string mutatedRegister = getRandomRegister();

        size_t pos = 0;
        while ((pos = mutatedInstruction.find(originalRegister, pos)) != std::string::npos) {
            mutatedInstruction.replace(pos, originalRegister.length(), mutatedRegister);
            pos += mutatedRegister.length();
        }
    } else if (mutationType == 1) {
        // Mutate an opcode (e.g., replace ADD with SUB)
        static const std::unordered_map<std::string, std::string> opcodeMutations = {
            {"ADD", "SUB"},
            {"SUB", "ADD"},
            {"XOR", "OR"},
            {"OR", "XOR"}
            // Add more opcode mutations as needed
        };
        for (const auto& mutation : opcodeMutations) {
            size_t pos = 0;
            while ((pos = mutatedInstruction.find(mutation.first, pos)) != std::string::npos) {
                mutatedInstruction.replace(pos, mutation.first.length(), mutation.second);
                pos += mutation.second.length();
            }
        }
    } else {
        // Mutate an operand (e.g., change a constant value)
        int pos = getRandomNumber(0, instruction.length() - 1);
        if (instruction[pos] >= '0' && instruction[pos] <= '9') {
            mutatedInstruction[pos] = '0' + getRandomNumber(0, 9); // Change to a random digit
        }
    }

    return mutatedInstruction;
}
std::string bytecodeObfuscation(const std::string& line) {
    std::string obfuscatedLine = line;  // Start with a copy of the original line
    
    // Define a set of equivalent instructions
    std::unordered_map<std::string, std::string> equivalentInstructions = {
        {"add", "sub"},
        {"sub", "add"},
        {"mov", "xor"},
        // Add more equivalent instructions as needed
    };

    // Search for known instructions and replace them with equivalents
    for (auto& entry : equivalentInstructions) {
        const std::string& originalInstruction = entry.first;
        const std::string& equivalentInstruction = entry.second;

        // Find and replace all occurrences of the original instruction with the equivalent
        size_t pos = 0;
        while ((pos = obfuscatedLine.find(originalInstruction, pos)) != std::string::npos) {
            obfuscatedLine.replace(pos, originalInstruction.length(), equivalentInstruction);
            pos += equivalentInstruction.length();
        }
    }

    // You can add more obfuscation techniques as needed
    
    return obfuscatedLine;
}


int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " input.s" << std::endl;
        return 1;
    }

    const std::string inputFileName = argv[1];
    std::ifstream inputFile(inputFileName);

    if (!inputFile) {
        std::cerr << "Error: Unable to open input file." << std::endl;
        return 1;
    }
    if (isFakeUPX(inputFileName)) {
        std::cerr << "Fake UPX header detected. Exiting." << std::endl;
        return 1;
    }

    std::vector<std::string> output;
    std::string line;
    std::unordered_set<std::string> generatedLabels;

    srand(static_cast<unsigned>(time(nullptr)));

    // Anti-Analysis Techniques: Check for debugger presence
    if (isDebuggerPresent() || isDebuggerAttachedThroughProcessEnum() || isDebuggerAttachedThroughTiming()) {
        std::cerr << "Debugger detected. Exiting." << std::endl;
        return 1;
    }

    // Load secret decryption key
    std::string decryptionKey = loadDecryptionKey();

    // Read input assembly file line by line
    std::vector<std::string> assemblyLines;
    while (std::getline(inputFile, line)) {
        assemblyLines.push_back(line);
    }

    // Detect the architecture
    if (!detectArchitecture(assemblyLines)) {
        std::cerr << "Input assembly is not x86-64. Exiting." << std::endl;
        return 1;
    }

    // Process each line of the assembly code
    for (const std::string& assemblyLine : assemblyLines) {
        if (assemblyLine.empty()) {
            // Blank line, ignore it
            output.push_back(assemblyLine);
        } else if (assemblyLine.find('.') == 0 || assemblyLine.back() == ':') {
            // It's a dot thing or label, ignore
            output.push_back(assemblyLine);
        } else if (assemblyLine.find('=') != std::string::npos) {
            // It's something like "Lset9 = Ltmp2-Leh_func_begin2," ignore it
            output.push_back(assemblyLine);
        } else {
            // It's an instruction, so insert obfuscators, random labels, garbage instructions,
            // and perform dynamic decryption and dynamic decompression

            std::string obfuscator = generateObfuscator();
            std::string label = generateRandomLabel();
            std::string garbageInstruction = generateGarbageInstruction();

            // Insert an unconditional jump to the label
            output.push_back(".byte 0xEB, 0x02, 0xEB, 0x01, 0x90\n");

            // Insert the label
            output.push_back(label + ":\n");

            // Insert the obfuscator
            output.push_back(".byte 0x" + obfuscator + "\n");

            // Insert garbage instruction
            output.push_back(garbageInstruction + "\n");

            // Perform dynamic decryption
            std::string decryptedLine = decryptLine(assemblyLine, decryptionKey);
            output.push_back(decryptedLine);

            // Perform dynamic decompression
            std::string decompressedLine = decompressLine(decryptedLine);
            output.push_back(decompressedLine);

            // Obfuscate constants
            std::string obfuscatedConstantsLine = obfuscateConstants(decompressedLine);
            output.push_back(obfuscatedConstantsLine);

            // Rename variables
            std::string renamedVariablesLine = renameVariables(obfuscatedConstantsLine);
            output.push_back(renamedVariablesLine);

            // Bytecode obfuscation
            std::string obfuscatedBytecodeLine = bytecodeObfuscation(renamedVariablesLine);
            output.push_back(obfuscatedBytecodeLine);

            // Check for long instruction
            if (isLongInstruction(obfuscatedBytecodeLine)) {
                // Create a de-obfuscation block
                std::string deobfuscationBlock = createDeobfuscationBlock(label, obfuscatedBytecodeLine);

                // Replace the long instruction with a call to the block
                std::string blockCall = replaceWithBlockCall(obfuscatedBytecodeLine, label);

                // Add the de-obfuscation block and block call to the output
                output.push_back(deobfuscationBlock);
                output.push_back(blockCall);
            } else {
                // No need for a de-obfuscation block, add the renamed instruction
                output.push_back(obfuscatedBytecodeLine);
            }

            // Split functions
            std::vector<std::string> splittedLines = splitFunction(std::vector<std::string>{obfuscatedBytecodeLine});
            
            // Lock the mutex before modifying shared resource
            mtx.lock();
            output.insert(output.end(), splittedLines.begin(), splittedLines.end());
            mtx.unlock(); // Unlock the mutex
        }
    }

    inputFile.close();

    std::vector<std::string> assemblyWithComplexJunk = addJunkPartitionsComplex(output);
    // Write the obfuscated assembly with complex junk partitions to a new file
    std::ofstream outputFile(inputFileName + "obf_with_complex_junk.s");
    for (const std::string& obfuscatedLine : assemblyWithComplexJunk) {
        outputFile << obfuscatedLine << std::endl;
    }
    outputFile.close();

    std::vector<std::string> mutatedAssembly = mutateAssembly(assemblyWithComplexJunk);
    // Write the mutated assembly to a new file
    std::ofstream mutatedOutputFile(inputFileName + "obf_with_mutations.s");
    for (const std::string& mutatedLine : mutatedAssembly) {
        mutatedOutputFile << mutatedLine << std::endl;
    }
    mutatedOutputFile.close();

    std::cout << "Obfuscated assembly with complex junk partitions saved to " << inputFileName + "obf_with_complex_junk.s" << std::endl;
    std::cout << "Mutated assembly saved to " << inputFileName + "obf_with_mutations.s" << std::endl;

    return 0;
}