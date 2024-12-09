#include <linux/types.h>
#include <bpf/bpf_helpers.h>

SEC("socket")
void bpf_func_ip()
{
	asm volatile(".byte 0xbf, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x85, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x63, 0x0a, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xbf, 0xa2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x07, 0x02, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff");
	asm volatile(".byte 0x18, 0x11, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x85, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xbf, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x15, 0x07, 0x8c, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x61, 0x69, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xbf, 0x91, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x07, 0x01, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x48, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x57, 0x00, 0x00, 0x00, 0xff, 0x3f, 0x00, 0x00");
	asm volatile(".byte 0x55, 0x00, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xbf, 0x91, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x07, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x50, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xbf, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x67, 0x08, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x77, 0x08, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x55, 0x08, 0x2a, 0x00, 0x2f, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x50, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xbf, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x67, 0x08, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x57, 0x08, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x0f, 0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x63, 0x86, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xbf, 0x89, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x67, 0x09, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x77, 0x09, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xbf, 0x91, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x07, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x48, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xbf, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x48, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xbf, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x57, 0x01, 0x00, 0x00, 0x40, 0x07, 0x00, 0x00");
	asm volatile(".byte 0x15, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x05, 0x00, 0x6d, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xbf, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x57, 0x02, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xb7, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x15, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xb7, 0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xbf, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x77, 0x02, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x57, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x0f, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x77, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x57, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x0f, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x0f, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x63, 0x26, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xb7, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x67, 0x07, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x77, 0x07, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x65, 0x07, 0x4e, 0x00, 0x46, 0x88, 0x00, 0x00");
	asm volatile(".byte 0x15, 0x07, 0x55, 0x00, 0x00, 0x08, 0x00, 0x00");
	asm volatile(".byte 0x15, 0x07, 0x55, 0x00, 0x00, 0x81, 0x00, 0x00");
	asm volatile(".byte 0x15, 0x07, 0x01, 0x00, 0xdd, 0x86, 0x00, 0x00");
	asm volatile(".byte 0x05, 0x00, 0x57, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xb7, 0x03, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x05, 0x00, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x7b, 0x0a, 0xd8, 0xff, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xbf, 0x91, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x07, 0x01, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x40, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x63, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xbf, 0x91, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x07, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x40, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x63, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x50, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x67, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x57, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x0f, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x63, 0x06, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x65, 0x08, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x15, 0x08, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x15, 0x08, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x05, 0x00, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xbf, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x18, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xb7, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x05, 0x00, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x15, 0x08, 0x08, 0x00, 0x06, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x15, 0x08, 0x07, 0x00, 0x11, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x15, 0x08, 0x01, 0x00, 0x29, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x05, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xbf, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x18, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xb7, 0x03, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x05, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x67, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x77, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x63, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x79, 0xa1, 0xd8, 0xff, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x63, 0x17, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x61, 0x71, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x67, 0x01, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x61, 0x72, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x4f, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x7b, 0x1a, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x61, 0x71, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x61, 0x72, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x67, 0x02, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x4f, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x7b, 0x2a, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xbf, 0xa2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x07, 0x02, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff");
	asm volatile(".byte 0x18, 0x11, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x85, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x15, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xb7, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xdb, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xdb, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x05, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xb7, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x7b, 0x1a, 0xe0, 0xff, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x7b, 0x1a, 0xe8, 0xff, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xbf, 0xa2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x07, 0x02, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff");
	asm volatile(".byte 0xbf, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x07, 0x03, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xff");
	asm volatile(".byte 0x18, 0x11, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xb7, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x85, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x05, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xbf, 0x71, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x07, 0x01, 0x00, 0x00, 0xb9, 0x77, 0xff, 0xff");
	asm volatile(".byte 0xb7, 0x02, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x2d, 0x12, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x15, 0x07, 0x04, 0x00, 0xa8, 0x88, 0x00, 0x00");
	asm volatile(".byte 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xb7, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xb7, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xbf, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x18, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x85, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00");
	asm volatile(".byte 0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
	asm volatile(".byte 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00");
}