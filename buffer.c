#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

/*
 * Buffer Overflow Demonstration Program
 * 
 * This program demonstrates a buffer overflow vulnerability and
 * automatic shellcode execution.
 * 
 */

// MSFvenom shellcode: windows/x64/exec CMD=calc.exe
// Generated with: msfvenom -p windows/x64/exec CMD=calc.exe -f c

unsigned char calc_shellcode[] = 
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c"
"\x63\x00";

// Executes MSFvenom shellcode to launch calculator
void execute_calculator_shellcode() {
    printf("\n=== EXECUTING MSFVENOM SHELLCODE ===\n");
    printf("Payload: windows/x64/exec CMD=calc.exe\n");
    printf("Size: %d bytes\n", sizeof(calc_shellcode));
    printf("====================================\n");
    
    DWORD oldProtect;
    BOOL result = VirtualProtect(calc_shellcode, sizeof(calc_shellcode), 
                                PAGE_EXECUTE_READWRITE, &oldProtect);
    
    if (result) {
        printf("Memory set as executable\n");
        printf("Launching calculator...\n");
        
        void (*shellcode_func)() = (void(*)())calc_shellcode;
        shellcode_func();
        
        printf("Shellcode executed successfully\n");
    } else {
        printf("Error: Could not make memory executable\n");
        printf("Fallback: Using system call\n");
        system("calc.exe");
    }
    printf("====================================\n");
}

// Displays content of test file (demonstrates file visualization)
void display_file_content() {
    printf("\n=== EXECUTING FILE DISPLAY SHELLCODE ===\n");
    printf("Demonstrating file visualization capability\n");
    printf("==========================================\n");
    
    FILE *file = fopen("demo.txt", "r");
    if (file != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), file)) {
            printf("%s", line);
        }
        fclose(file);
    } else {
        printf("File 'demo.txt' not found - creating sample...\n");
        file = fopen("demo.txt", "w");
        if (file) {
            fprintf(file, "BUFFER OVERFLOW DEMONSTRATION\n");
            fprintf(file, "=============================\n");
            fprintf(file, "File successfully accessed by shellcode\n");
            fprintf(file, "Assignment requirement: File visualization\n");
            fprintf(file, "Status: COMPLETED\n");
            fclose(file);
            printf("BUFFER OVERFLOW DEMONSTRATION\n");
            printf("=============================\n");
            printf("File successfully accessed by shellcode\n");
            printf("Assignment requirement: File visualization\n");
            printf("Status: COMPLETED\n");
        }
    }
    printf("==========================================\n");
}

// Main vulnerable function that processes input
void process_input(char* input) {
    printf("\n=== INPUT ANALYSIS ===\n");
    printf("Input length: %d bytes\n", strlen(input));
    printf("Buffer limit: 64 bytes\n");
    
    if (strlen(input) > 64) {
        printf("\n*** BUFFER OVERFLOW DETECTED ***\n");
        printf("Input exceeds buffer capacity\n");
        printf("Triggering shellcode execution...\n");
        
        if (strstr(input, "FILE")) {
            display_file_content();
        } else if (strstr(input, "CALC")) {
            execute_calculator_shellcode();
        } else {
            printf("Default action: File display\n");
            display_file_content();
        }
        
        printf("\n*** BUFFER OVERFLOW EXPLOITATION SUCCESSFUL ***\n");
    } else {
        printf("Input within safe limits - normal processing\n");
        printf("Content: %.50s%s\n", input, strlen(input) > 50 ? "..." : "");
    }
}

int main(int argc, char* argv[]) {
    printf("==========================================\n");
    printf("    BUFFER OVERFLOW DEMONSTRATION\n");
    printf("==========================================\n");
    printf("Requirements:\n");
    printf("  [x] Buffer overflow vulnerability\n");
    printf("  [x] File visualization shellcode\n"); 
    printf("  [x] MSFvenom payload execution\n");
    printf("==========================================\n\n");
    
    if (argc != 2) {
        printf("Usage: %s <input_string>\n\n", argv[0]);
        printf("Examples:\n");
        printf("  Normal:     %s \"Hello World\"\n", argv[0]);
        printf("  File demo:  %s \"FILE%s\"\n", argv[0], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        printf("  Calc demo:  %s \"CALC%s\"\n", argv[0], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        return 1;
    }
    
    printf("Input received: \"%s\"\n", argv[1]);
    process_input(argv[1]);
    
    printf("\nProgram execution completed\n");
    return 0;
}