#include <stdio.h>
#include "libbpf/src/libbpf.h"

const char hex[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b',
                    'c', 'd', 'e', 'f'};

int write_new_insns(FILE *out_file, const char *insns_filename);

int main(int argc, char *argv[])
{
    struct bpf_object *obj = bpf_object__open(argv[1]);
    if (!obj) {
        return 1;
    }
    FILE *file = fopen("out.c", "w");
    if (!file) {
        bpf_object__close(obj);
        return 1;
    }
    fwrite("#include <linux/types.h>\n#include <bpf/bpf_helpers.h>\n\n",
            sizeof(char), 55, file);
    struct bpf_program *prog;
    int current_index = 2;
    bpf_object__for_each_program(prog, obj) {
        // Write the program section name
        const char *section_name = bpf_program__section_name(prog);
        fwrite("SEC(\"", sizeof(char), 5, file);
        fwrite(section_name, sizeof(char), strlen(section_name), file);
        fwrite("\")\n", sizeof(char), 3, file);
        // Write the program name
        const char *name = bpf_program__name(prog);
        fwrite("void ", sizeof(char), 5, file);
        fwrite(name, sizeof(char), strlen(name), file);
        fwrite("()\n{\n", sizeof(char), 5, file);
        // Write the program instructions
        if (write_new_insns(file, argv[current_index]) != 0) {
            bpf_object__close(obj);
            fclose(file);
            return 1;
        }
        // Write the end of the function
        fwrite("}\n\n", sizeof(char), 3, file);
        ++current_index;
    }
    bpf_object__close(obj);
    /* Instead of writing a static license, we could also query for the specific
     * -license to avoid edge cases.
     */
    fwrite("char _license[] SEC(\"license\") = \"GPL\";\n",sizeof(char), 40,
            file);
    fclose(file);
    return 0;
}

void byte_to_hex(char buffer[], unsigned char byte)
{
    buffer[0] = '0';
    buffer[1] = 'x';
    buffer[2] = hex[byte >> 4];  // Same as byte / 16
    buffer[3] = hex[byte & 0xF]; // Same as byte % 16
    buffer[4] = '\0';
}

int write_new_insns(FILE *out_file, const char *insns_filename)
{
    FILE *insns_file = fopen(insns_filename, "r");
    if (!insns_file) {
        return 1;
    }
    ssize_t len = 0;
    char *line = NULL;
    size_t n = 0;
    while ((len = getline(&line, &n, insns_file)) > 0) {
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
        unsigned char code, src_reg, dst_reg;
        signed short off;
        signed int imm;
        if (sscanf(line, "{%hhu %hhu %hhu %hd %d}", &code, &src_reg, &dst_reg, &off, &imm) != 5) {
            fclose(insns_file);
            return 1;
        }
        char byte_1[5], byte_2[5], byte_3[5], byte_4[5], byte_5[5], byte_6[5],
             byte_7[5], byte_8[5];
        byte_to_hex(byte_1, code);
        byte_to_hex(byte_2, (src_reg << 4) | dst_reg);
        byte_to_hex(byte_3, off & 0xFF);
        byte_to_hex(byte_4, (off >> 8) & 0xFF);
        byte_to_hex(byte_5, imm & 0xFF);
        byte_to_hex(byte_6, (imm >> 8) & 0xFF);
        byte_to_hex(byte_7, (imm >> 16) & 0xFF);
        byte_to_hex(byte_8, (imm >> 24) & 0xFF);
        fprintf(out_file, "\tasm volatile(\".byte %s, %s, %s, %s, %s, %s, %s, %s\");\n",
                           byte_1, byte_2, byte_3, byte_4, byte_5, byte_6,
                           byte_7, byte_8);
    }
    fclose(insns_file);
    return 0;
}