#include <stdio.h>
#include <mach-o/loader.h>

#define PRINT_SIZE(type) { printf("sizeof("#type") %zu\n", sizeof(type)); }

int main() {
    PRINT_SIZE(cpu_type_t);
    PRINT_SIZE(cpu_subtype_t);
    PRINT_SIZE(struct mach_header_64);
    PRINT_SIZE(vm_prot_t);
    PRINT_SIZE(struct segment_command_64);
    PRINT_SIZE(struct section_64);

    printf("CPU_TYPE_ARM64 %x\n", CPU_TYPE_ARM64);
}
