#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/time.h>
#include <SDL2/SDL.h>
#include <GL/gl.h>

//#define DOOMU
#define DOOM2

// window
#define WIDTH	(320 * 3)
#define HEIGHT	(240 * 3)
// audio
#define WITH_SOUND	16
// some options
//#define DISABLE_MOUSE_Y

// doom original, do not change
#define DOOM_WIDTH	320
#define DOOM_HEIGHT	200
#define TEX_WIDTH	512

// DOS emulation
#define DPMI_MAX_MEMORY_REPORT	(32*1024*1024)
#define DPMI_PAGE_SIZE	4096
#define FIRST_HANDLE	3
#define MAX_FILES	4

//#define DUMP_RELOC
//#define LUMP_CACHE_HOOK

// The Ultimate Doom
#ifdef DOOMU
#define EXE_PATH	"DOOM.EXE"
#define DOOM_LE_19	0x027ACC
#define CODE_OBJ	0
#define DATA_OBJ	2
#define FILE_DATA_OFFS	10424	// 233056: SpawnFly; 222632
#define CUSTOM_EIP	0x001535a5 // __CMain
#define PTR_ARGC	0x001535E1
#define PTR_ARGV	0x001535DC
#endif
// Doom 2
#ifdef DOOM2
#define EXE_PATH	"DOOM2.EXE"
#define DOOM_LE_19	0x027ACC
#define CODE_OBJ	0
#define DATA_OBJ	2
#define FILE_DATA_OFFS	10424	// 233056: SpawnFly; 222632
#define CUSTOM_EIP	0x00153395 // __CMain
#define PTR_ARGC	0x001533d1
#define PTR_ARGV	0x001533cc
#endif

#define LE_MAGIC	0x454c

typedef union
{
	uint32_t ex;
	uint16_t x;
	struct
	{
		uint8_t l, h;
	};
} reg32_t;
#define CTX_REG(x)	((reg32_t*)&ctx->uc_mcontext.gregs[x])

typedef struct
{
	uint16_t magic;
	uint8_t byte_order; // 0 = little endian
	uint8_t word_order; // 0 = little endian
	uint32_t format_level;
	uint16_t cpu_type;
	uint16_t target_os;
	uint32_t mod_version;
	uint32_t mod_flags;
	uint32_t page_count;
	uint32_t init_cs;
	uint32_t init_eip;
	uint32_t init_ss;
	uint32_t init_esp;
	uint32_t page_size;
	uint32_t last_page_size;
	uint32_t fixup_size;
	uint32_t fixup_checksum;
	uint32_t loader_size;
	uint32_t loader_checksum;
	uint32_t object_table_offs;
	uint32_t object_table_count;
	uint32_t object_page_map_offset;
	uint32_t object_iterate_data_map_offset;
	uint32_t resource_tab_offset;
	uint32_t resource_tab_count;
	uint32_t resident_names_table_offset;
	uint32_t entry_table_offset;
	uint32_t module_directives_offset;
	uint32_t module_directives_count;
	uint32_t fixup_page_table_offset;
	uint32_t fixup_record_table_offset;
	uint32_t imported_modules_name_table_offset;
	uint32_t imported_modules_count;
	uint32_t imported_procedure_name_table_offset;
	uint32_t page_checksum_table_offset;
	uint32_t data_pages_offset;
	uint32_t preload_page_count;
	uint32_t nresident_names_table_offset;
	uint32_t nresident_names_table_length;
	uint32_t nresident_names_table_checksum;
	uint32_t automatic_data_object;
	uint32_t debug_information_offset;
	uint32_t debug_information_length;
	uint32_t preload_instance_pages_number;
	uint32_t demand_instance_pages_number;
	uint32_t extra_heap_allocation;
	uint32_t unknown;
} __attribute__((packed)) le_header_t;

typedef struct
{
	uint32_t virtual_size;
	uint32_t relocation_base;
	uint32_t flags;
	uint32_t page_map_idx;
	uint32_t page_map_count;
	uint32_t unknown;
} __attribute__((packed)) le_object_t;

typedef struct
{
	uint8_t src;
	uint8_t dst;
	int16_t offs_src; // memory to overwrite
	uint8_t object;
	uint16_t offs_dst; // value to write
} __attribute__((packed)) reloc_32bit_16offs_t;

typedef struct
{
	uint8_t src;
	uint8_t dst;
	int16_t offs_src; // memory to overwrite
	uint8_t object;
	uint32_t offs_dst; // value to write
} __attribute__((packed)) reloc_32bit_32offs_t;

typedef union
{
	struct
	{
		uint8_t src, dst;
	};
	reloc_32bit_16offs_t r32bit_16offs;
	reloc_32bit_32offs_t r32bit_32offs;
} __attribute__((packed)) reloc_type_t;

typedef struct
{
	uint32_t eip;
	uint32_t esp;
} base_info_t;

typedef struct
{
	void *ptr;
	uint32_t base;
	size_t size;
} mapobj_t;

typedef struct
{
	uint32_t max_avail; // Largest available free block in bytes
	uint32_t max_unlocked; // Maximum unlocked page allocation in pages
	uint32_t max_locked; // Maximum locked page allocation in pages
	uint32_t max_linear; // Linear address space size in pages
	uint32_t total_unlocked; // Total number of unlocked pages
	uint32_t total_free; // Total number of free pages
	uint32_t total_total; // Total number of physical pages
	uint32_t free_linear; // Free linear address space in pages
	uint32_t paging_size; // Size of paging file/partition in pages
	uint32_t reserved[3];
} dpmi_meminfo_t;

enum
{
	P_JMP,	// replace 5 bytes with jmp and 32bit relative offset
	P_ADDR, // keep 1 byte same and replace next 4 with 32bit relative offset
	P_NOPS, // NOPs in various amounts
	P_UINT32, // raw uint32_t value
	P_UINT16, // raw uint16_t value
	P_UINT8, // raw uint8_t value

	P_UPDATE, // just patch destination pointers address - no EXE patching

	PDATA = (DATA_OBJ << 16), // patch in data page
};

typedef struct
{
	uint32_t addr;
	uint32_t type;
	void *func;
} hook_t;

typedef struct
{
	uint8_t r, g, b;
} __attribute__((packed)) palcol_t;

typedef struct
{
	uint32_t type;
	uint32_t data1;
	uint32_t data2;
	uint32_t data3;
} doom_event_t;

enum
{
	ev_keydown,
	ev_keyup,
	ev_mouse,
	ev_joystick
};

typedef struct
{
	uint8_t name[8];
	uint32_t handle;
	uint32_t offs;
	uint32_t size;
} lump_info_t;

SDL_Window *sdl_win;
SDL_GLContext sdl_context;
int texture;
uint32_t pixels[TEX_WIDTH * DOOM_HEIGHT];
const palcol_t *palette;

const dpmi_meminfo_t dpmi_info =
{
	DPMI_MAX_MEMORY_REPORT,
	DPMI_MAX_MEMORY_REPORT / DPMI_PAGE_SIZE,
	DPMI_MAX_MEMORY_REPORT / DPMI_PAGE_SIZE,
	DPMI_MAX_MEMORY_REPORT / DPMI_PAGE_SIZE,
	DPMI_MAX_MEMORY_REPORT / DPMI_PAGE_SIZE,
	DPMI_MAX_MEMORY_REPORT / DPMI_PAGE_SIZE,
	DPMI_MAX_MEMORY_REPORT / DPMI_PAGE_SIZE,
	DPMI_MAX_MEMORY_REPORT / DPMI_PAGE_SIZE,
	1, // or zero?
	{-1, -1, -1}
};

base_info_t info;
mapobj_t memory[2]; // TODO: replace with 'obj'
le_object_t obj[3]; // TODO: better name
uint32_t fixup_for_page[128];
uint8_t fixup_temp[8*1024];

uint64_t segfaults;

mapobj_t doom_zone;

int file_handles[MAX_FILES];

uint8_t timer_enabled;
void (*timer_func)();

#define DOS_ALLOC_START	0x00010000
#define DOS_ALLOC_END	0x00060000	// this is limited by VGA remap
#define DOS_ALLOC_SIZE	(DOS_ALLOC_END - DOS_ALLOC_START)
void *dos_memory;
uint32_t dos_alloc_pos = DOS_ALLOC_START;
uint32_t dos_alloc_free = DOS_ALLOC_SIZE;

#define VGA_PAGE_SIZE	(64*1024)
#define VGA_MEMORY_SIZE	(VGA_PAGE_SIZE*5)
#define VGA_MEMORY_BASE	0x000A0000
#define VGA_TEMP_REMAP	0x00200000
uint8_t vga_sequencer;
uint8_t vga_crtc;
uint8_t vga_graphics;
uint8_t *vga_memory;

uint8_t vga_seq_04 = 0b00000100; // only this mode is supported
uint8_t vga_gfx_05 = 0b00010000; // only this mode is supported

const uint32_t vga_page_start[] =
{
	// this table contains offsets to remap entire VGA memory block
	// memory is remapped backwards so selected block is always VGA_MEMORY_BASE location
	// it is not possible to select multiple blocks at once
	VGA_MEMORY_BASE - 4 * VGA_PAGE_SIZE, // hidden access
	VGA_MEMORY_BASE - 0 * VGA_PAGE_SIZE, // page 0
	VGA_MEMORY_BASE - 1 * VGA_PAGE_SIZE, // page 1
	VGA_MEMORY_BASE - 4 * VGA_PAGE_SIZE, // impossible (1 | 2)
	VGA_MEMORY_BASE - 2 * VGA_PAGE_SIZE, // page 2
	VGA_MEMORY_BASE - 4 * VGA_PAGE_SIZE, // impossible (1 | 4)
	VGA_MEMORY_BASE - 4 * VGA_PAGE_SIZE, // impossible (2 | 4)
	VGA_MEMORY_BASE - 4 * VGA_PAGE_SIZE, // impossible (1 | 2 | 4)
	VGA_MEMORY_BASE - 3 * VGA_PAGE_SIZE, // page 3
	VGA_MEMORY_BASE - 4 * VGA_PAGE_SIZE, // impossible (1 | 8)
	VGA_MEMORY_BASE - 4 * VGA_PAGE_SIZE, // impossible (2 | 8)
	VGA_MEMORY_BASE - 4 * VGA_PAGE_SIZE, // impossible (1 | 2 | 8)
	VGA_MEMORY_BASE - 4 * VGA_PAGE_SIZE, // impossible (4 | 8)
	VGA_MEMORY_BASE - 4 * VGA_PAGE_SIZE, // impossible (1 | 4 | 8)
	VGA_MEMORY_BASE - 4 * VGA_PAGE_SIZE, // impossible (2 | 4 | 8)
	VGA_MEMORY_BASE - 4 * VGA_PAGE_SIZE, // impossible (1 | 2 | 4 | 8)
};

#ifdef WITH_SOUND
uint8_t *snd_ptr[WITH_SOUND];
uint8_t *snd_end[WITH_SOUND];
uint8_t snd_volr[WITH_SOUND];
uint8_t snd_voll[WITH_SOUND];
uint8_t snd_step[WITH_SOUND];
uint8_t snd_rate[WITH_SOUND];
#endif

static void hook_TODO();
static void hook_exit();
static void hook_I_Error(const char*, ...);
void hook_malloc(); // asm.S
void hook_realloc(); // asm.S
void hook_free(); // asm.S
void hook_I_SetPalette(); // asm.S
void hook_I_GetTime(); // asm.S
void hook_I_ZoneBase(); // asm.S
void handle_input(); // asm.S
void D_PostEvent(doom_event_t*); // asm.S
#ifdef WITH_SOUND
void hook_I_StartSound(); // asm.S
void hook_I_SoundIsPlaying(); // asm.S
void hook_I_UpdateSoundParams(); // asm.S
void hook_I_StopSound(); // asm.S
#endif

uint32_t doom_D_PostEvent;

#ifdef LUMP_CACHE_HOOK
void hook_W_CacheLumpNum_enter(); // asm.S
void hook_W_CacheLumpNum_leave(); // asm.S
uint32_t doom_W_CacheLumpNum;
uint32_t ex_cache_lump_num;
#endif

const hook_t hooks[] =
{
	// The Ultimate Doom
#ifdef DOOMU
	{0x000411F9, P_JMP, hook_exit}, // entire function
	{0x00040812, P_JMP, hook_malloc}, // '_nmalloc_' entire function
	{0x0004087D, P_JMP, hook_free}, // '_nfree_' entire function
	{0x000410F3, P_JMP, hook_realloc}, // '_nrealloc_' entire function
	{0x0001ab10, P_JMP, hook_I_Error}, // 'I_Error' entire function
	{0x0001B700, P_UINT8, (void*)0xC3}, // 'I_StartupSound' disable entire function
	{0x00019c10, P_JMP, hook_I_GetTime}, // 'I_GetTime' entire function
	{0x00019ca0, P_JMP, hook_I_SetPalette}, // 'I_SetPalette' entire function
	{0x0001adb0, P_UINT8, (void*)0xC3}, // 'I_BeginRead' entire function (disk icon)
	{0x0001aea0, P_UINT8, (void*)0xC3}, // 'I_EndRead' entire function (remove disk icon)
	{0x0001a006, P_JMP, handle_input}, // end of 'I_FinishUpdate'
	{0x0001b236, P_NOPS, (void*)2}, // weird stuck loop

	// caled from here
	{0x0001d0f0, P_UPDATE, &doom_D_PostEvent},

#ifdef WITH_SOUND
	// sound support
	{0x0003f53b, P_ADDR, hook_I_StartSound},
	{0x0001b320, P_JMP, hook_I_SoundIsPlaying}, // entire function
	{0x0003f6e0, P_ADDR, hook_I_UpdateSoundParams},
	{0x0003eff5, P_ADDR, hook_I_StopSound},
	{0x000295cc, P_UINT32 | PDATA, (void*)3}, // force wave sound type
#endif

	// extra
	{0x0001ac20, P_JMP, hook_I_ZoneBase}, // replace 'I_ZoneBase' for code execution exploit

	// modify P_SpawnMapThing - clean map (no items)
//	{0x00031aed, P_UINT16, (void*)0xDB33},

#ifdef LUMP_CACHE_HOOK
	// exploit search helper
	{0x00038e40, P_JMP, hook_W_CacheLumpNum_enter}, // redirect entire function
	{0x00038e46, P_UPDATE, &doom_W_CacheLumpNum}, // jump back address
	{0x00038e99, P_JMP, hook_W_CacheLumpNum_leave}, // redirect the ending
#endif

#endif
	// Doom 2
#ifdef DOOM2
	//{0x000411F9, P_JMP, hook_exit}, // entire function
	{0x00040602, P_JMP, hook_malloc}, // '_nmalloc_' entire function
	{0x0004066D, P_JMP, hook_free}, // '_nfree_' entire function
	{0x00040EE3, P_JMP, hook_realloc}, // '_nrealloc_' entire function
	{0x0001AB10, P_JMP, hook_I_Error}, // 'I_Error' entire function
	{0x0001B700, P_UINT8, (void*)0xC3}, // 'I_StartupSound' disable entire function
	{0x00019C10, P_JMP, hook_I_GetTime}, // 'I_GetTime' entire function
	{0x00019CA0, P_JMP, hook_I_SetPalette}, // 'I_SetPalette' entire function
	{0x0001adb0, P_UINT8, (void*)0xC3}, // 'I_BeginRead' entire function (disk icon)
	{0x0001aea0, P_UINT8, (void*)0xC3}, // 'I_EndRead' entire function (remove disk icon)
	{0x0001a006, P_JMP, handle_input}, // end of 'I_FinishUpdate'
	{0x0001b236, P_NOPS, (void*)2}, // weird stuck loop

	// caled from here
	{0x0001D0E0, P_UPDATE, &doom_D_PostEvent},

#ifdef WITH_SOUND
	// sound support
	{0x0003F34B, P_ADDR, hook_I_StartSound},
	{0x0001b320, P_JMP, hook_I_SoundIsPlaying}, // entire function
	{0x0003F4F0, P_ADDR, hook_I_UpdateSoundParams},
	{0x0003EE05, P_ADDR, hook_I_StopSound},
	{0x000291f8, P_UINT32 | PDATA, (void*)3}, // force wave sound type
#endif

	// extra
	{0x0001AC20, P_JMP, hook_I_ZoneBase}, // replace 'I_ZoneBase' for code execution exploit

	// modify P_SpawnMapThing - clean map (no items)
//	{0x000319ad, P_UINT16, (void*)0xDB33},
#endif


	// TESTING ONLY
//	{0x00023D40, P_UINT8, (void*)0xC3}, // 'M_Drawer' entire function

	{0} // TERMINATOR
};

void apply_page_reloc(int fd, le_object_t *obj, void *mem, uint32_t rec_base, uint32_t rec_end)
{
	uint32_t size = rec_end - rec_base;
	uint8_t *ptr = fixup_temp;
	uint8_t *end = fixup_temp + size;
	uint32_t *data;
	uint32_t tmp;

#ifdef DUMP_RELOC
	printf("new fixup base address: 0x%08X\n", mem);
#endif

	if(size > sizeof(fixup_temp))
	{
		printf("Fixup memory too small! Need %uB.\n", size);
		return;
	}

	lseek(fd, rec_base, SEEK_SET);
	read(fd, fixup_temp, size);

	while(ptr < end)
	{
		reloc_type_t *rel = (void*)ptr;
		switch(rel->src)
		{
			case 0x07: // 32-bit Offset fixup (32-bits)
				switch(rel->dst)
				{
					case 0x00:
						data = mem + rel->r32bit_16offs.offs_src;
						tmp = obj[rel->r32bit_16offs.object-1].relocation_base + rel->r32bit_16offs.offs_dst;
#ifdef DUMP_RELOC
						printf("[R] 32bit reloc\n offs_src 0x%04X\n offs_dst 0x%04X\n object %d\n", rel->r32bit_16offs.offs_src, rel->r32bit_16offs.offs_dst, rel->r32bit_16offs.object);
						printf(" (0x%08X) 0x%08X -> 0x%08X\n", (uint32_t)data, *data, tmp);
#endif
						*data = tmp;
						ptr += sizeof(reloc_32bit_16offs_t);
					break;
					case 0x10:
						data = mem + rel->r32bit_32offs.offs_src;
						tmp = obj[rel->r32bit_32offs.object-1].relocation_base + rel->r32bit_32offs.offs_dst;
#ifdef DUMP_RELOC
						printf("[R] 32bit reloc\n offs_src 0x%04X\n offs_dst 0x%08X\n object %d\n", rel->r32bit_32offs.offs_src, rel->r32bit_32offs.offs_dst, rel->r32bit_32offs.object);
						printf(" (0x%08X) 0x%08X -> 0x%08X\n", (uint32_t)data, *data, tmp);
#endif
						*data = tmp;
						ptr += sizeof(reloc_32bit_32offs_t);
					break;
					default:
						printf("Unknown 32bit relocation dst: 0x%02X!\n", rel->dst);
						return;
					break;
				}
			break;
			default:
				printf("Unknown relocation src 0x%02X dst 0x%02X!\n", rel->src, rel->dst);
			return; // end
		}
	}
}

void apply_reloc(int fd, le_object_t *obj, int oid, int pagesize, int frto)
{
	uint32_t page = obj[oid].page_map_idx - 1; // MEH tables
	uint32_t page_i = 0;
	uint32_t count = obj[oid].page_map_count;

	while(count--)
	{
#ifdef DUMP_RELOC
		printf("[R] PAGE %d =========\n", page + obj[oid].page_map_idx - 1);
#endif
		apply_page_reloc(fd, obj, (void*)obj[oid].relocation_base + page_i * pagesize, frto + fixup_for_page[page], frto + fixup_for_page[page+1]);
		page++;
		page_i++;
	}
}

int load_exe(const char *fn)
{
	int fd, i;
	uint32_t le_base = DOOM_LE_19;
	le_header_t le;

	fd = open(fn, O_RDONLY);
	if(fd < 0)
	{
		printf("- failed to open %s\n", fn);
		return 1;
	}

	// linear executable header
	lseek(fd, le_base, SEEK_SET);
	i = read(fd, &le, sizeof(le));
	if(i != sizeof(le_header_t) || le.magic != LE_MAGIC)
	{
		printf("- %s is not DOOM version 1.9\n", fn);
		close(fd);
		return 1;
	}

#if 1
	printf("LE info\n");
	printf("endianess %d, %d\n", le.byte_order, le.word_order);
	printf("CPU %d\n", le.cpu_type);
	printf("OS %d\n", le.target_os);
	printf("version %d flags 0x%04X\n", le.mod_version, le.mod_flags);

	printf("page count %d size %d last_size %d\n", le.page_count, le.page_size, le.last_page_size);

	printf("init: CS 0x%08X; EIP 0x%08X; SS 0x%08X; ESP 0x%08X\n", le.init_cs, le.init_eip, le.init_ss, le.init_esp);

	printf("fixup size %d; page table offs %d record table offs %d\n", le.fixup_size, le.fixup_page_table_offset, le.fixup_record_table_offset);
	printf("loader size %d\n", le.loader_size);

	printf("object table: offs %d count %d pagemapoffs %d iter %d\n", le.object_table_offs, le.object_table_count, le.object_page_map_offset, le.object_iterate_data_map_offset);

	printf("resource table: offs %d count %d\n", le.resource_tab_offset, le.resource_tab_count);

	printf("resident names table offset %d\n", le.resident_names_table_offset);

	printf("entry table offset %d\n", le.entry_table_offset);

	printf("module directives: offset %d count %d\n", le.module_directives_offset, le.module_directives_count);

	printf("imports name tab: offset %d count %d\n", le.imported_modules_name_table_offset, le.imported_modules_count);

	printf("data pages offset %d\n", le.data_pages_offset);

	printf("automatic data %d\n", le.automatic_data_object);

	printf("debug info: offs %d len %d\n", le.debug_information_offset, le.debug_information_length);

	printf("preload %d\n", le.preload_instance_pages_number);
	printf("demand %d\n", le.demand_instance_pages_number);

	printf("extra heap %d\n", le.extra_heap_allocation);

	lseek(fd, le_base + le.object_table_offs, SEEK_SET);
	for(int i = 0; i < le.object_table_count; i++)
	{
		read(fd, &obj[0], sizeof(le_object_t));
		printf("OBJ %d\n", i);
		printf(" size %d\n base 0x%08X\n flags 0x%08X\n pagemap %d %d\n unkn %d\n", obj[0].virtual_size, obj[0].relocation_base, obj[0].flags, obj[0].page_map_idx, obj[0].page_map_count, obj[0].unknown);
	}
#endif

	// some checks; TODO: more checks; (identification, memory overflows ...)
/*	if(le.object_table_count != 3)
	{
		printf("- %s is not DOOM version 1.9\n", fn);
		close(fd);
		return 1;
	}
*/
	// load object table
	lseek(fd, le_base + le.object_table_offs, SEEK_SET);
	read(fd, obj, sizeof(le_object_t) * le.object_table_count);

	// remap memory - data area collides with video memory
	obj[CODE_OBJ].relocation_base |= 0x00100000;
	obj[DATA_OBJ].relocation_base |= 0x00100000;

	// map memory: code
	memory[0].size = ((obj[CODE_OBJ].virtual_size + le.page_size - 1) / le.page_size) * le.page_size;
	memory[0].ptr = mmap((void*)obj[CODE_OBJ].relocation_base, memory[0].size, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if(memory[0].ptr == MAP_FAILED)
	{
		printf("- memory map 0 failed\n");
		close(fd);
		return 1;
	}

	// map memory: data
	memory[1].size = ((obj[DATA_OBJ].virtual_size + le.page_size - 1) / le.page_size) * le.page_size;
	memory[1].ptr = mmap((void*)obj[DATA_OBJ].relocation_base, memory[1].size, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if(memory[1].ptr == MAP_FAILED)
	{
		printf("- memory map 1 failed\n");
		munmap(memory[0].ptr, memory[0].size);
		close(fd);
		return 1;
	}

	// debug
	printf("OBJ %d at 0x%08X\n", CODE_OBJ, memory[0].ptr);
	printf("OBJ %d at 0x%08X\n", DATA_OBJ, memory[1].ptr);

	// fix the base
	le.data_pages_offset += le_base - le.page_size;
	le.data_pages_offset -= FILE_DATA_OFFS;

	// load: code
	lseek(fd, le.data_pages_offset + obj[CODE_OBJ].page_map_idx * le.page_size, SEEK_SET);
	i = read(fd, memory[0].ptr, obj[CODE_OBJ].page_map_count * le.page_size);
	printf("CODE: read %dB\n", i);

	// load: data
	lseek(fd, le.data_pages_offset + obj[DATA_OBJ].page_map_idx * le.page_size, SEEK_SET);
	i = read(fd, memory[1].ptr, obj[DATA_OBJ].page_map_count * le.page_size);
	printf("DATA: read %dB\n", i);

	// load fixup for pages
	lseek(fd, le_base + le.fixup_page_table_offset, SEEK_SET);
	i = read(fd, fixup_for_page, (le.page_count + 1) * sizeof(uint32_t));

	// relocation
	le.fixup_record_table_offset += le_base;
	apply_reloc(fd, obj, CODE_OBJ, le.page_size, le.fixup_record_table_offset);
	apply_reloc(fd, obj, DATA_OBJ, le.page_size, le.fixup_record_table_offset);

	// fill stuff
	info.eip = le.init_eip + obj[le.init_cs - 1].relocation_base;
	info.esp = le.init_esp + obj[le.init_ss - 1].relocation_base;
#ifdef CUSTOM_EIP
	info.eip = CUSTOM_EIP;
#endif

	close(fd);

	printf("EXE loaded ...\n");

	// DOS memory
	dos_memory = mmap((void*)DOS_ALLOC_START, DOS_ALLOC_SIZE, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	printf("got DOS memory %p ...\n", dos_memory);

	// video memory; page 0 selected now
	vga_memory = mmap((void*)VGA_MEMORY_BASE, VGA_MEMORY_SIZE, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	printf("got VGA memory %p ...\n", vga_memory);

	return 0;
}

//
// keyboard

int keys_sdl2doom(int sym)
{
	switch(sym)
	{
		case SDLK_LEFT:
			return 0xAC;
		case SDLK_RIGHT:
			return 0xAE;
		case SDLK_DOWN:
			return 0xAF;
		case SDLK_UP:
			return 0xAD;
		case SDLK_ESCAPE:
			return 0x1B;
		case SDLK_RETURN:
			return 0x0D;
		case SDLK_TAB:
			return 0x09;
		case SDLK_BACKSPACE:
		case SDLK_DELETE:
			return 0x7F;
		case SDLK_PAUSE:
			return 0xFF;
		case SDLK_LSHIFT:
//		case SDLK_RSHIFT:
			return 0xB6;
		case SDLK_LCTRL:
		case SDLK_RCTRL:
			return 0x9D;
		case SDLK_LALT:
		case SDLK_RALT:
			return 0xB8;
		default:
			if(sym >= SDLK_KP_0 && sym <= SDLK_KP_9)
				return '0' + sym - SDLK_KP_0;
			if(sym >= SDLK_SPACE && sym <= SDLK_z)
				return sym;
		break;
	}
	return 0;
}

void sdl_input()
{
	int doom_key;
	SDL_Event event;
	static doom_event_t evt;
	static doom_event_t mvt; // mouse

	mvt.type = 0;
	mvt.data2 = 0;
	mvt.data3 = 0;

	while(SDL_PollEvent(&event))
	{
		if(event.type == SDL_QUIT)
			exit(0);
		switch(event.type)
		{
			case SDL_KEYDOWN:
				doom_key = keys_sdl2doom(event.key.keysym.sym);
				if(doom_key)
				{
					evt.type = ev_keydown;
					evt.data1 = doom_key;
					D_PostEvent(&evt);
				} else
				if(event.key.keysym.sym == SDLK_RSHIFT)
				{
					// for "auto run"
					evt.type = ev_keydown; // no keydown for this
					evt.data1 = 0xB6;
					D_PostEvent(&evt);
				} else
#if 1
				if(event.key.keysym.sym == SDLK_KP_ENTER)
				{
					// dump entire static data area
					printf("DATA DUMP\n");
					int fd = open("dump.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
					if(fd >= 0)
					{
						write(fd, (void*)obj[DATA_OBJ].relocation_base, ((obj[DATA_OBJ].virtual_size + 4096 - 1) / 4096) * 4096);
						close(fd);
					}

					// dump entire lump cache
#ifdef DOOMU
					uint32_t num_lumps = *((uint32_t*)(0x00075374 + obj[DATA_OBJ].relocation_base));
					lump_info_t *linfo = *((lump_info_t**)(0x00075378 + obj[DATA_OBJ].relocation_base));
					uint32_t *lcache = *((uint32_t**)(0x00075368 + obj[DATA_OBJ].relocation_base));
#endif
#ifdef DOOM2
					uint32_t num_lumps = *((uint32_t*)(0x00074FA0 + obj[DATA_OBJ].relocation_base));
					lump_info_t *linfo = *((lump_info_t**)(0x00074FA4 + obj[DATA_OBJ].relocation_base));
					uint32_t *lcache = *((uint32_t**)(0x00074F94 + obj[DATA_OBJ].relocation_base));
#endif

					printf("LUMP CACHE DUMP\n");
					fd = open("lumpcache.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
					if(fd >= 0)
					{
						for(int i = 0; i < num_lumps; i++, linfo++, lcache++)
						{
							if(*lcache)
							{
								// add full name
								write(fd, linfo->name, 8);
								// add pointer
								write(fd, lcache, 4);
							}
						}
						close(fd);
					}
				}
				if(event.key.keysym.sym == SDLK_KP_PLUS)
				{
					// HACK
					printf("VRAM DUMP\n");
					int fd = open("vram.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
					if(fd >= 0)
					{
						write(fd, vga_memory, VGA_PAGE_SIZE * 4);
						close(fd);
					}
				}
#endif
			break;
			case SDL_KEYUP:
				doom_key = keys_sdl2doom(event.key.keysym.sym);
				if(doom_key)
				{
					evt.type = ev_keyup;
					evt.data1 = doom_key;
					D_PostEvent(&evt);
				}
			case SDL_MOUSEBUTTONDOWN:
				if(event.button.button == SDL_BUTTON_LEFT)
					mvt.data1 |= 1;
				if(event.button.button == SDL_BUTTON_RIGHT)
					mvt.data1 |= 2;
				if(event.button.button == SDL_BUTTON_MIDDLE)
					mvt.data1 |= 4;
				mvt.type = ev_mouse;
			break;
			case SDL_MOUSEBUTTONUP:
				if(event.button.button == SDL_BUTTON_LEFT)
					mvt.data1 &= ~1;
				if(event.button.button == SDL_BUTTON_RIGHT)
					mvt.data1 &= ~2;
				if(event.button.button == SDL_BUTTON_MIDDLE)
					mvt.data1 &= ~4;
				mvt.type = ev_mouse;
			break;
			case SDL_MOUSEMOTION:
				mvt.type = ev_mouse;
				mvt.data2 += event.motion.xrel * 4;
#ifndef DISABLE_MOUSE_Y
				mvt.data3 -= event.motion.yrel * 4;
#endif
			break;
		}
	}

	if(mvt.type == ev_mouse)
		D_PostEvent(&mvt);
}

//
// Doom code replacements

#ifdef LUMP_CACHE_HOOK
void W_CacheLumpNum(int ptr)
{
	printf("W_CacheLumpNum %d = 0x%08X\n", ex_cache_lump_num, ptr);
}
#endif

void *I_ZoneBase(uint32_t size)
{
	// this is only used when code execution support is ON
	doom_zone.size = size;
	doom_zone.ptr = mmap(NULL, size, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	printf("[I_ZoneBase] %dB at 0x%08X of RWX memory\n", size, doom_zone.ptr);
	return doom_zone.ptr;
}

#ifdef WITH_SOUND
void sound_mix(void *userdata, int16_t *output, int len)
{
	int16_t *oend = output + len / 2;

	while(output < oend)
	{
		int left = 0;
		int right = 0;

		for(int i = 0; i < WITH_SOUND; i++)
		{
			if(snd_ptr[i] >= snd_end[i])
				continue;

			int sample = *snd_ptr[i];
			sample = (sample - 128) * 256;

			left += (snd_voll[i] * sample) / 255;
			right += (snd_volr[i] * sample) / 255;

			snd_step[i]--;
			if(!snd_step[i])
			{
				snd_ptr[i]++;
				snd_step[i] = snd_rate[i];
			}
		}

		if(left > 0x7FFF)
			left = 0x7FFF;
		if(left < -0x7FFF)
			left = -0x7FFF;
		if(right > 0x7FFF)
			right = 0x7FFF;
		if(right < -0x7FFF)
			right = -0x7FFF;

		*output++ = left;
		*output++ = right;
	}
}

void I_UpdateSoundParams(uint32_t slot, uint32_t sep, uint32_t volume)
{
	int left, right;

	if(slot >= WITH_SOUND)
		return;

	sep += 1;
	left = volume - ((volume * sep * sep) >> 16);
	sep -= 257;
	right = volume - ((volume * sep * sep) >> 16);

	snd_voll[slot] = left;
	snd_volr[slot] = right;
}

void I_StopSound(uint32_t slot)
{
	if(slot >= WITH_SOUND)
		return;
	snd_end[slot] = NULL;
}

int I_SoundIsPlaying(uint32_t slot)
{
	if(slot >= WITH_SOUND)
		return 0;
	return snd_ptr[slot] < snd_end[slot];
}

int I_StartSound(uint32_t sfx_id, uint16_t *data, uint32_t volume, uint32_t sep, uint32_t slot)
{
	uint32_t len;

	if(slot >= WITH_SOUND)
		return -1;

	if(data[0] != 3)
		return -1;

	len = *((uint32_t*)&data[2]);
	if(len < 32)
		return -1;

	switch(data[1])
	{
		case 11025:
			snd_rate[slot] = 4;
		break;
		case 22050:
			snd_rate[slot] = 2;
		break;
		case 44100:
			snd_rate[slot] = 1;
		break;
		default:
			return -1;
	}

	snd_step[slot] = 8;
	snd_end[slot] = NULL;
	snd_ptr[slot] = (uint8_t*)data + 0x18;
	snd_end[slot] = (uint8_t*)data + 0x18 + len - 32;

	I_UpdateSoundParams(slot, sep, volume);

	return slot;
}
#else
void I_StartSound() {}
void I_SoundIsPlaying() {}
void I_UpdateSoundParams() {}
void I_StopSound() {}
#endif

void I_SetPalette(const void *data)
{
	palette = data;
}

void redraw_screen(uint8_t start)
{
	uint32_t *dst;
	uint8_t *src;

	if(!palette)
		return;

	for(int i = 0; i < 4; i++)
	{
		src = vga_memory + (start << 8) + i * 0x10000;
		dst = pixels + i;
		for(int y = 0; y < DOOM_HEIGHT; y++)
		{
			for(int x = 0; x < DOOM_WIDTH / 4; x++)
			{
				palcol_t c = palette[*src];
				*dst = c.r | (c.g << 8) | (c.b << 16);
				dst += 4;
				src++;
			}
			dst += TEX_WIDTH - DOOM_WIDTH;
		}
	}

	glBindTexture(GL_TEXTURE_2D, texture);
	glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, TEX_WIDTH, DOOM_HEIGHT, 0, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);

	glMatrixMode(GL_MODELVIEW);
	glLoadIdentity();

	glBegin(GL_TRIANGLE_STRIP);
		glTexCoord2f(0.0f, 0.0f);
		glVertex3i(0.0f, 0.0f, 0);
		glTexCoord2f((float)DOOM_WIDTH / (float)TEX_WIDTH, 0.0f);
		glVertex3i(1.0f, 0.0f, 0);
		glTexCoord2f(0.0f, 1.0f);
		glVertex3i(0.0f, 1.0f, 0);
		glTexCoord2f((float)DOOM_WIDTH / (float)TEX_WIDTH, 1.0f);
		glVertex3i(1.0f, 1.0f, 0);
	glEnd();

	SDL_GL_SwapWindow(sdl_win);
}

//
// HOOKS

static void hook_TODO()
{
	printf("HOOK TODO\n");
	exit(1);
}

static void hook_exit()
{
	printf("* exit from EXE *\n");
	exit(0);
}

static void hook_I_Error(const char *txt, ...)
{
	va_list	argptr;

	printf("\n================ I_Error ================\n");

	va_start(argptr, txt);
	vfprintf(stderr, txt, argptr);
	fprintf(stderr, "\n");
	va_end(argptr);

	fflush(stderr);

	exit(1);
}

//
// DOS file handles

static uint16_t fd_create(int fd)
{
	for(int i = 0; i < MAX_FILES; i++)
	{
		if(file_handles[i] < 0)
		{
			// free slot
			file_handles[i] = fd;
			return i + FIRST_HANDLE;
		}
	}
	// full
	close(fd);
	return 0xFFFF;
}

static int fd_find(uint16_t handle)
{
	handle -= FIRST_HANDLE;
	if(handle >= MAX_FILES)
		return -1;
	return file_handles[handle];
}

static void fd_close(uint16_t handle)
{
	handle -= FIRST_HANDLE;
	if(handle >= MAX_FILES)
		return;
	close(file_handles[handle]);
	file_handles[handle] = -1;
}

//
// DOS stuff

static void dump_stack(ucontext_t *ctx, int count)
{
	uint32_t *esp = (uint32_t*)ctx->uc_mcontext.gregs[REG_ESP];
	while(count--)
		printf(" 0x%08X\n", *esp++);
}

static void dump_regs(ucontext_t *ctx, int read_eip)
{
	uint8_t *eip = (uint8_t*)ctx->uc_mcontext.gregs[REG_EIP];

	if(read_eip)
		printf("EIP: 0x%08X: 0x%02X\n", (uint32_t)eip, *eip);
	else
		printf("EIP: 0x%08X\n", (uint32_t)eip);
	printf("EAX: 0x%08X\n", ctx->uc_mcontext.gregs[REG_EAX]);
	printf("EBX: 0x%08X\n", ctx->uc_mcontext.gregs[REG_EBX]);
	printf("ECX: 0x%08X\n", ctx->uc_mcontext.gregs[REG_ECX]);
	printf("EDX: 0x%08X\n", ctx->uc_mcontext.gregs[REG_EDX]);
	printf("ESI: 0x%08X\n", ctx->uc_mcontext.gregs[REG_ESI]);
	printf("EDI: 0x%08X\n", ctx->uc_mcontext.gregs[REG_EDI]);
	printf("EBP: 0x%08X\n", ctx->uc_mcontext.gregs[REG_EBP]);
	printf("ESP: 0x%08X\n", ctx->uc_mcontext.gregs[REG_ESP]);
}

static void handle_out(uint16_t addr, uint8_t value)
{
	switch(addr)
	{
		case 0x3d4: // VGA CRTC - register select
			vga_crtc = value;
		break;
		case 0x3d5: // VGA CRTC - register write
			switch(vga_crtc)
			{
				case 0x0C:
					redraw_screen(value);
				break;
				default:
					printf("[VGA] unsupported CRTC 0x%02X write 0x%02X\n", vga_crtc, value);
				break;
			}
		break;
		case 0x3C4:
			// VGA sequencer - register select
			vga_sequencer = value;
		break;
		case 0x3C5:
			// VGA sequencer - register write
			switch(vga_sequencer)
			{
				case 2: // select map; THIS COLLIDES WITH 'select read'
					// first remap somewhere free
					vga_memory = mremap(vga_memory, VGA_MEMORY_SIZE, VGA_MEMORY_SIZE, MREMAP_MAYMOVE | MREMAP_FIXED, (void*)VGA_TEMP_REMAP);
					// then remap where VGA needs it
					vga_memory = mremap(vga_memory, VGA_MEMORY_SIZE, VGA_MEMORY_SIZE, MREMAP_MAYMOVE | MREMAP_FIXED, vga_page_start[value & 15]);
				break;
				case 4:
					vga_seq_04 = value;
					goto unsup_seq;
				default:
unsup_seq:
					printf("[VGA] unsupported sequencer 0x%02X write 0x%02X\n", vga_sequencer, value);
				break;
			}
		break;
		case 0x03CE:
			// VGA graphics - register select
			vga_graphics = value;
		break;
		case 0x03CF:
			// VGA graphics - register write
			switch(vga_graphics)
			{
				case 0x04: // select read; THIS COLLIDES WITH 'select map'
					// first remap somewhere free
					vga_memory = mremap(vga_memory, VGA_MEMORY_SIZE, VGA_MEMORY_SIZE, MREMAP_MAYMOVE | MREMAP_FIXED, (void*)VGA_TEMP_REMAP);
					// then remap where VGA needs it
					vga_memory = mremap(vga_memory, VGA_MEMORY_SIZE, VGA_MEMORY_SIZE, MREMAP_MAYMOVE | MREMAP_FIXED, vga_page_start[1 << (value & 3)]);
				break;
				case 0x05:
					vga_gfx_05 = value;
				break;
				default:
					printf("[VGA] unsupported graphics 0x%02X write 0x%02X\n", vga_graphics, value);
				break;
			}
		break;
		default:
//			printf("TODO: out(0x%04X, 0x%02X)\n", addr, value);
		break;
	}
}

static uint8_t handle_in(uint16_t addr)
{
	switch(addr)
	{
		case 0x3c5: // VGA sequencer - register read
			switch(vga_sequencer)
			{
				case 4:
					return vga_seq_04;
				default:
					printf("[VGA] unsupported sequencer read 0x%02X\n", vga_sequencer);
				break;
			}
		break;
		case 0x03CF: // VGA graphics - register read
			switch(vga_graphics)
			{
				case 0x05:
					return vga_gfx_05;
				default:
					printf("[VGA] unsupported graphics read 0x%02X\n", vga_graphics);
				break;
			}
		break;
		case 0x3d5: // VGA CRTC - register read
			printf("[VGA] unsupported CRTC read 0x%02X\n", vga_crtc);
		break;
		default:
//			printf("TODO: in(0x%04X)\n", addr);
		break;
	}
	return 0;
}

static void handle_int31(ucontext_t *ctx)
{
	ctx->uc_mcontext.gregs[REG_EFL] |= 1; // set carry flag

	switch(CTX_REG(REG_EAX)->x)
	{
		case 0x0600:
		case 0x0601:
			// lock / unlock - ignore with success
			ctx->uc_mcontext.gregs[REG_EFL] &= ~1; // clear carry flag
		break;
		case 0x0500:
			// memory info request
			memcpy((void*)ctx->uc_mcontext.gregs[REG_EDI], (void*)&dpmi_info, sizeof(dpmi_info));
			ctx->uc_mcontext.gregs[REG_EFL] &= ~1; // clear carry flag
		break;
		case 0x0300:
			printf("[DPMI] CALL IRQ 0x%08X\n", CTX_REG(REG_EBX)->l);
			exit(1);
		break;
		case 0x0100:
		{
			// allocate DOS memory
			uint32_t size = CTX_REG(REG_EBX)->x * 16;
			if(size < dos_alloc_free)
			{
				// reserve the space
				dos_alloc_free -= size;
				// report 
				CTX_REG(REG_EAX)->x = dos_alloc_pos / 16;
				CTX_REG(REG_EDX)->x = 0;
				ctx->uc_mcontext.gregs[REG_EFL] &= ~1; // clear carry flag
				//
				printf("[DPMI] allocated %dB of DOS memory at 0x%08X\n", size, dos_alloc_pos);
				// advance the pointer
				dos_alloc_pos += size;
			} else
			{
				// fail
				ctx->uc_mcontext.gregs[REG_EFL] |= 1; // set carry flag
				// error report
				CTX_REG(REG_EAX)->x = 8; // insufficient memory
				CTX_REG(REG_EBX)->x = dos_alloc_free / 16;
				//
				printf("[DPMI] DOS memory alloc of %dB failed, have only %d\n", size, dos_alloc_free);
			}
		}
		break;
		default:
			printf("UNSUPPORTED DPMI COMMAND 0x%04X\n", CTX_REG(REG_EAX)->x);
			dump_regs(ctx, 0);
			exit(1);
		break;
	}
}

static void dos_ioctl(ucontext_t *ctx)
{
	switch(CTX_REG(REG_EAX)->l)
	{
		case 0: // get device info
		{
			if(CTX_REG(REG_EBX)->x <= 2) // stdout & stderr && stdin
			{
				CTX_REG(REG_EDX)->x = 0b0100100010100010;
				ctx->uc_mcontext.gregs[REG_EFL] &= ~1; // clear carry flag
				break;
			}

			struct stat st;

			if(fstat(CTX_REG(REG_EBX)->x, &st))
			{
				// error
				CTX_REG(REG_EAX)->x = 2; // invalid handle
				ctx->uc_mcontext.gregs[REG_EFL] |= 1; // set carry flag
			}

			CTX_REG(REG_EDX)->x = 0b0000100000000000;
			ctx->uc_mcontext.gregs[REG_EFL] &= ~1; // clear carry flag
		}
		break;
		default:
			printf("UNSUPPORTED DOS IOCTL 0x%02X\n", CTX_REG(REG_EAX)->l);
			exit(1);
		break;
	}
}

static void handle_int10(ucontext_t *ctx)
{
	switch(CTX_REG(REG_EAX)->h)
	{
		case 0x00: // set video mode
			printf("SET VIDEO MODE 0x%02X\n", CTX_REG(REG_EAX)->l);
		break;
		case 0x02: // set cursor position // TODO
		break;
		case 0x03: // read cursor position // TODO
			CTX_REG(REG_ECX)->x = 0;
			CTX_REG(REG_EDX)->x = 0;
		break;
		case 0x09: // write character with attribute // TODO: attribute
		{
#if 0
			int count = CTX_REG(REG_ECX)->x;
			while(count--)
				fputc(CTX_REG(REG_EAX)->l, stdout);
			fflush(stdout);
#endif
		}
		break;
		default:
			printf("UNSUPPORTED INT 0x10: AH 0x%02X; EIP: 0x%08X\n", CTX_REG(REG_EAX)->h, ctx->uc_mcontext.gregs[REG_EIP]);
			exit(1);
		break;
	}
}

static void handle_int21(ucontext_t *ctx)
{
	int tmp;

	switch(CTX_REG(REG_EAX)->h)
	{
/*		case 0x09: // print; '$' terminated
		{
			uint8_t *ptr = (uint8_t*)ctx->uc_mcontext.gregs[REG_EDX];
			while(*ptr != '$')
				ptr++;
			write(STDOUT_FILENO, (void*)ctx->uc_mcontext.gregs[REG_EDX], ptr - (uint8_t*)ctx->uc_mcontext.gregs[REG_EDX]);
		}
		break;
		case 0x30: // get DOS version
			CTX_REG(REG_EBX)->h = CTX_REG(REG_EAX)->l == 1 ? 0xFD : 0x00;
			CTX_REG(REG_EAX)->x = 0x0A07; // DOS 7.10
			CTX_REG(REG_EBX)->l = 42; // revision
			CTX_REG(REG_ECX)->x = 0;
		break;*/
		case 0x25: // set IRQ
			switch(CTX_REG(REG_EAX)->l)
			{
				case 0x08: // timer
					timer_func = (void*)ctx->uc_mcontext.gregs[REG_EDX];
/*					timer_enabled |= 2;
					if(!(timer_enabled & 4))
					{
						// actually start the timer
						struct itimerval tv =
						{
							.it_interval = {.tv_usec = },
							.it_value = {.tv_usec = },
						};
						setitimer(ITIMER_REAL, );
					}*/
				break;
				default:
					printf("SET IRQ 0x%02X TO 0x%08X\n", CTX_REG(REG_EAX)->l, ctx->uc_mcontext.gregs[REG_EDX]);
				break;
			}
		break;
		case 0x35: // get IRQ
			ctx->uc_mcontext.gregs[REG_EBX] = 0; // NULL - no function
			switch(CTX_REG(REG_EAX)->l)
			{
				case 0x09: // keyboard
				case 0x08: // timer
				break;
				default:
					printf("GET IRQ 0x%02X\n", CTX_REG(REG_EAX)->l);
				break;
			}
		break;
		case 0x3D: // open file
		{
			int fd, mode;
			switch(CTX_REG(REG_EAX)->l & 3)
			{
				case 0:
					mode = O_RDONLY;
				break;
				case 1:
					mode = O_WRONLY | O_TRUNC | O_CREAT; // is this correct?
				break;
				case 2:
					mode = O_RDWR | O_CREAT;
				break;
				default:
					printf("FILE OPEN BAD MODE\n");
					ctx->uc_mcontext.gregs[REG_EFL] |= 1; // set carry flag
					CTX_REG(REG_EAX)->x = 2; // file not found
					return;
				break;
			}

			printf("OPEN FILE '%s' MODE %d\n", ctx->uc_mcontext.gregs[REG_EDX], CTX_REG(REG_EAX)->l);

			fd = open((void*)ctx->uc_mcontext.gregs[REG_EDX], mode, 0644);
			if(fd >= 0)
			{
				mode = fd_create(fd);
				if(mode == 0xFFFF)
					fd = -1;
			}
			if(fd < 0)
			{
				// error
				ctx->uc_mcontext.gregs[REG_EFL] |= 1; // set carry flag
				CTX_REG(REG_EAX)->x = 12; // invalid access
				return;
			}
			CTX_REG(REG_EAX)->x = mode;
			ctx->uc_mcontext.gregs[REG_EFL] &= ~1; // clear carry flag
		}
		break;
		case 0x3E: // close file
			fd_close(CTX_REG(REG_EBX)->x);
			ctx->uc_mcontext.gregs[REG_EFL] &= ~1; // clear carry flag
		break;
		case 0x3F: // io read
		{
			if(CTX_REG(REG_EBX)->x <= 2)
			{
				// error
				CTX_REG(REG_EAX)->x = 2; // invalid handle
				ctx->uc_mcontext.gregs[REG_EFL] |= 1; // set carry flag
//				printf("INVALID READ HANDLE %d\n", CTX_REG(REG_EBX)->x);
//				exit(1);
			}
			tmp = read(fd_find(CTX_REG(REG_EBX)->x), (void*)ctx->uc_mcontext.gregs[REG_EDX], CTX_REG(REG_ECX)->ex);
			if(tmp < 0)
			{
				// error
				CTX_REG(REG_EAX)->x = 2; // invalid handle
				ctx->uc_mcontext.gregs[REG_EFL] |= 1; // set carry flag
				return;
			}
			CTX_REG(REG_EAX)->ex = tmp;
			ctx->uc_mcontext.gregs[REG_EFL] &= ~1; // clear carry flag
		}
		break;
		case 0x40: // io write
			if(CTX_REG(REG_EBX)->x <= 1) // stdout & stderr
			{
				ctx->uc_mcontext.gregs[REG_EFL] &= ~1; // clear carry flag
				CTX_REG(REG_EAX)->x = write(STDOUT_FILENO, (void*)ctx->uc_mcontext.gregs[REG_EDX], CTX_REG(REG_ECX)->x);
				return;
			}
			tmp = write(fd_find(CTX_REG(REG_EBX)->x), (void*)ctx->uc_mcontext.gregs[REG_EDX], CTX_REG(REG_ECX)->ex);
			if(tmp < 0)
			{
				// error
				CTX_REG(REG_EAX)->x = 2; // invalid handle
				ctx->uc_mcontext.gregs[REG_EFL] |= 1; // set carry flag
				return;
			}
			CTX_REG(REG_EAX)->ex = tmp;
			ctx->uc_mcontext.gregs[REG_EFL] &= ~1; // clear carry flag
		break;
		case 0x42: // io seek
		{
			int wh;
			off_t offs;

			if(CTX_REG(REG_EBX)->x <= 1) // stdout & stderr
			{
				// seek ignored
				ctx->uc_mcontext.gregs[REG_EFL] &= ~1; // clear carry flag
				CTX_REG(REG_EAX)->x = 0;
				return;
			}

			switch(CTX_REG(REG_EAX)->l & 3)
			{
				case 0:
					wh = SEEK_SET;
				break;
				case 1:
					wh = SEEK_CUR;
				break;
				case 2:
					wh = SEEK_END;
				break;
				default:
					printf("FILE SEEK BAD MODE\n");
					ctx->uc_mcontext.gregs[REG_EFL] |= 1; // set carry flag
					CTX_REG(REG_EAX)->x = 19; // seek error
				break;
			}

			offs = (CTX_REG(REG_ECX)->x << 16) | CTX_REG(REG_EDX)->x;
			offs = lseek(fd_find(CTX_REG(REG_EBX)->x), offs, wh);
			if(offs == (off_t)-1)
			{
				// error
				CTX_REG(REG_EAX)->x = 2; // invalid handle
				ctx->uc_mcontext.gregs[REG_EFL] |= 1; // set carry flag
				return;
			}
			CTX_REG(REG_EDX)->x = offs >> 16;
			CTX_REG(REG_EAX)->x = offs;
		}
		break;
		case 0x43: // file attributes
			if(CTX_REG(REG_EAX)->l == 0x00)
			{
				// get
				struct stat st;
//				printf("get file attr '%s'\n", ctx->uc_mcontext.gregs[REG_EDX]);
				if(stat((void*)ctx->uc_mcontext.gregs[REG_EDX], &st) || S_ISDIR(st.st_mode))
				{
					// not found
					CTX_REG(REG_EAX)->x = 2; // file not found
					ctx->uc_mcontext.gregs[REG_EFL] |= 1; // set carry flag
					break;
				}
				ctx->uc_mcontext.gregs[REG_EFL] &= ~1; // clear carry flag
				CTX_REG(REG_ECX)->x = 0;
			} else
			{
				printf("UNSUPPORTED 'file attributes' command 0x%02X\n", CTX_REG(REG_EAX)->l);
				exit(1);
			}
		break;
		case 0x44: // ioctl
			dos_ioctl(ctx);
		break;
		case 0x4C:
			printf("* exit code 0x%02X *\n", CTX_REG(REG_EAX)->l);
			exit(0);
		break;
		case 0x57: // set date / time
			// ignored
			ctx->uc_mcontext.gregs[REG_EFL] &= ~1; // clear carry flag
		break;
		default:
			printf("UNSUPPORTED INT 0x21: AH 0x%02X\n", CTX_REG(REG_EAX)->h);
			dump_regs(ctx, 0);
			exit(1);
		break;
	}
}

static void sigsegv(int sig, siginfo_t *si, void *uc)
{
	ucontext_t *ctx = (ucontext_t*)uc;
	uint8_t *eip = (uint8_t*)ctx->uc_mcontext.gregs[REG_EIP];

	segfaults++;

	if(eip >= (uint8_t*)memory[0].ptr && eip < (uint8_t*)memory[0].ptr + memory[0].size)
	{
		switch(*eip)
		{
			case 0xCD: // 'int'
				switch(eip[1])
				{
					case 0x10:
						handle_int10(ctx);
					break;
					case 0x21:
						handle_int21(ctx);
					break;
					case 0x31:
						handle_int31(ctx);
					break;
					case 0x33:
						// mouse - report not present
						CTX_REG(REG_EAX)->x = 0;
					break;
					default:
						printf("UNSUPPORTED 'INT 0x%02X' CALLED\n", eip[1]);
						goto regdump;
					break;
				}
				ctx->uc_mcontext.gregs[REG_EIP] = (uint32_t)(eip + 2);
			return;
			case 0xEE: // out    %al,(%dx)
				handle_out(CTX_REG(REG_EDX)->x, CTX_REG(REG_EAX)->l);
				ctx->uc_mcontext.gregs[REG_EIP] = (uint32_t)(eip + 1);
			return;
			case 0xEC: // in     (%dx),%al
				CTX_REG(REG_EAX)->l = handle_in(CTX_REG(REG_EDX)->x);
				ctx->uc_mcontext.gregs[REG_EIP] = (uint32_t)(eip + 1);
			return;
			case 0x66:
				ctx->uc_mcontext.gregs[REG_EIP] = (uint32_t)(eip + 2);
				switch(eip[1])
				{
					case 0xEF: // out    %ax,(%dx)
						handle_out(CTX_REG(REG_EDX)->x, CTX_REG(REG_EAX)->l);
						handle_out(CTX_REG(REG_EDX)->x + 1, CTX_REG(REG_EAX)->h);
					return;
					default:
						printf("INVALID OUT 0x%02X\n", eip[1]);
						exit(1);
					break;
				}
			break;
/*			case 0xFA: // cli
				ctx->uc_mcontext.gregs[REG_EIP] = (uint32_t)(eip + 1);
				timer_enabled &= ~1;
			return;
*/			default:
unhandled:
				printf("UNHANDLED SIGSEGV\n");
regdump:
				dump_regs(ctx, 1);
				dump_stack(ctx, 32);
				exit(1);
			break;
		}
	}

	printf("UNHANDLED SIGSEGV\n");
	dump_regs(ctx, 1);//0);
	dump_stack(ctx, 16);
	exit(1);
}

static void sigint(int sig, siginfo_t *si, void *uc)
{
	ucontext_t *ctx = (ucontext_t*)uc;
	printf("FORCED EXIT\nSegfaults total: %lu\n", segfaults);
	dump_regs(ctx, 0);
	dump_stack(ctx, 16);
	exit(1);
}

int init_video()
{
	// init video
	if(SDL_Init(SDL_INIT_EVERYTHING) != 0)
	{
		printf("SDL INIT error\n");
		return 1;
	}

	sdl_win = SDL_CreateWindow("DOOM TEST", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, WIDTH, HEIGHT, SDL_WINDOW_OPENGL);

	SDL_GLContext Context = SDL_GL_CreateContext(sdl_win);

	glViewport(0, 0, WIDTH, HEIGHT);
	glShadeModel(GL_SMOOTH);
	glHint(GL_PERSPECTIVE_CORRECTION_HINT, GL_NICEST);
	glClearColor(0.0f, 0.0f, 0.0f, 0.0f);
	glClearDepth(0.0f);

	glMatrixMode(GL_PROJECTION);
	glLoadIdentity();
	glOrtho(0.0f, 1.0f, 1.0f, 0.0f, 1.0f, -1.0f);

	glEnable(GL_TEXTURE_2D);
	glGenTextures(1, &texture);

	SDL_SetWindowGrab(sdl_win, 1);
	SDL_SetRelativeMouseMode(1);

	return 0;
}

int main(int argc, void **argv)
{
	if(!load_exe(EXE_PATH))
	{
		if(init_video())
			return 1;
		memset(file_handles, 0xFF, sizeof(file_handles));
		{
			// install signal handler
			struct sigaction sa;

			sa.sa_flags = SA_SIGINFO;
			sigemptyset(&sa.sa_mask);
			sa.sa_sigaction = sigsegv;
			sigaction(SIGSEGV, &sa, NULL);

			sa.sa_flags = SA_SIGINFO;
			sigemptyset(&sa.sa_mask);
			sa.sa_sigaction = sigint;
			sigaction(SIGINT, &sa, NULL);
		}
		{
			// apply 'jmp'
			const hook_t *hook = hooks;
			while(hook->addr)
			{
				uint32_t addr = hook->addr;
				addr += obj[hook->type >> 16].relocation_base;

				switch(hook->type & 0xFFFF)
				{
					case P_JMP:
						// place 'jmp'
						*((uint8_t*)addr) = 0xE9;
						// fall trough
					case P_ADDR:
						// place relative address
						*((uint32_t*)(addr+1)) = (uint32_t)hook->func - (addr + 5);
					break;
					case P_NOPS:
						memset((void*)addr, 0x90, (uint32_t)hook->func);
					break;
					case P_UINT8:
						*((uint8_t*)addr) = (uint32_t)hook->func;
					break;
					case P_UINT16:
						*((uint16_t*)addr) = (uint32_t)hook->func;
					break;
					case P_UINT32:
						*((uint32_t*)addr) = (uint32_t)hook->func;
					break;
					case P_UPDATE:
						// local variable update - not an EXE patch
						*((uint32_t*)hook->func) = addr;
					break;
				}
				
				hook++;
			}
		}
#ifdef WITH_SOUND
		{
			SDL_AudioSpec fmt;

			fmt.freq = 44100;
			fmt.format = AUDIO_S16;
			fmt.channels = 2;
			fmt.samples = 512;
			fmt.callback = (void*)sound_mix;
			fmt.userdata = NULL;

			if(SDL_OpenAudio(&fmt, NULL) < 0)
				return 1;

			SDL_PauseAudio(0);
		}
#endif
		// overwrite argument pointers
#ifdef PTR_ARGC
		*((uint32_t*)PTR_ARGC) = (uint32_t)&argc;
#endif
#ifdef PTR_ARGV
		*((uint32_t*)PTR_ARGV) = (uint32_t)&argv;
#endif
		// testing breakpoint
//		*((uint16_t*)0x00140ee0) = 0x00CD; // INT 0x00
		// start the game
		void (*func)() = (void*)info.eip;
		printf("starting from 0x%08X\n", info.eip);
		func();
		pause();
	}

	// cleanup
	if(memory[0].ptr)
		munmap(memory[0].ptr, memory[0].size);
	if(memory[1].ptr)
		munmap(memory[1].ptr, memory[1].size);

	return 0;
}

