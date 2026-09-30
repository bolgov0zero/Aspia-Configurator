// Aspia Host Portable — лаунчер-стаб.
//
// Собирается ОДИН раз (scripts/build-portable-stub.sh, при установке сервиса) и переиспользуется
// для всех сборок: Aspia Configurator просто дописывает MSI-пакет в конец уже скомпилированного
// stub.exe (см. app/portable_build.py) — как это делают 7z SFX / NSIS, без перекомпиляции на
// каждый запрос.
//
// Формат хвоста файла (последние 16 байт): [8 байт длины MSI, little-endian][8 байт магии "ASPIAPX1"].
// Сам MSI лежит перед этим хвостом.
//
// Поведение при запуске:
//   1. читает сам себя, извлекает MSI во временный файл;
//   2. msiexec /i <temp>\package.msi /quiet — тихая установка (сервис ставится и стартует сам);
//   3. запускает %ProgramFiles%\Aspia\Host\aspia_host.exe — штатный GUI хоста, коннектится к
//      уже поднятой службе и открывает окно; у найденного окна извне (без внедрения в процесс)
//      убирается кнопка сворачивания — в Portable-сценарии нужны только два состояния, «открыто»
//      и «закрыто», без промежуточного «висит в трее»;
//   4. ждёт сигнала «готово»: окно стало невидимым (крестик — по умолчанию у самой программы это
//      hideToTray(), но раз сворачивания нет, для пользователя это и есть закрытие) ИЛИ процесс
//      реально завершился (Exit в трее с подтверждением, снятие задачи в диспетчере);
//   5. msiexec /x <тот же temp-файл> /quiet — тихое удаление: служба, файлы, реестр;
//   6. чистит %ProgramData%\aspia (см. шаг 5 в wWinMain — это не MSI-компонент);
//   7. подчищает временный каталог.
//
// requireAdministrator в манифесте (launcher.manifest) даёт один UAC-запрос на старте — дальше
// весь процесс, включая шаг 5, уже выполняется от администратора без повторных запросов.
//
// Важно: крестик закрывает Portable даже при активных сессиях и не спрашивает подтверждения (в
// отличие от штатного Exit) — это осознанный выбор для одноразового сценария, не ошибка.
#include <windows.h>
#include <shlobj.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdint.h>

#define TRAILER_SIZE 16
static const unsigned char kMagic[8] = { 'A','S','P','I','A','P','X','1' };

static void fail(const wchar_t* message)
{
    MessageBoxW(NULL, message, L"Aspia Host Portable", MB_OK | MB_ICONERROR);
}

// Извлекает MSI-пакет, дописанный в хвост этого же exe, во временный файл. Возвращает 1 при успехе.
static int extractPayload(const wchar_t* dest_path)
{
    wchar_t self_path[MAX_PATH];
    if (!GetModuleFileNameW(NULL, self_path, MAX_PATH))
    {
        fail(L"Не удалось определить путь к самому себе.");
        return 0;
    }

    HANDLE src = CreateFileW(self_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (src == INVALID_HANDLE_VALUE)
    {
        fail(L"Не удалось открыть себя для чтения.");
        return 0;
    }

    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(src, &file_size) || file_size.QuadPart < TRAILER_SIZE)
    {
        CloseHandle(src);
        fail(L"Файл повреждён (слишком маленький).");
        return 0;
    }

    LARGE_INTEGER trailer_pos;
    trailer_pos.QuadPart = file_size.QuadPart - TRAILER_SIZE;
    if (!SetFilePointerEx(src, trailer_pos, NULL, FILE_BEGIN))
    {
        CloseHandle(src);
        fail(L"Не удалось прочитать хвост файла.");
        return 0;
    }

    unsigned char trailer[TRAILER_SIZE];
    DWORD read = 0;
    if (!ReadFile(src, trailer, TRAILER_SIZE, &read, NULL) || read != TRAILER_SIZE)
    {
        CloseHandle(src);
        fail(L"Не удалось прочитать хвост файла.");
        return 0;
    }

    if (memcmp(trailer + 8, kMagic, 8) != 0)
    {
        CloseHandle(src);
        fail(L"В файл не встроен пакет — похоже, это просто заготовка лаунчера "
             L"без вшитого MSI. Соберите файл через Aspia Configurator.");
        return 0;
    }

    uint64_t payload_len = 0;
    memcpy(&payload_len, trailer, 8);

    if ((LONGLONG)payload_len + TRAILER_SIZE > file_size.QuadPart)
    {
        CloseHandle(src);
        fail(L"Файл повреждён (неверная длина пакета).");
        return 0;
    }

    LARGE_INTEGER payload_pos;
    payload_pos.QuadPart = file_size.QuadPart - TRAILER_SIZE - (LONGLONG)payload_len;
    if (!SetFilePointerEx(src, payload_pos, NULL, FILE_BEGIN))
    {
        CloseHandle(src);
        fail(L"Не удалось перейти к началу пакета внутри файла.");
        return 0;
    }

    HANDLE dst = CreateFileW(dest_path, GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (dst == INVALID_HANDLE_VALUE)
    {
        CloseHandle(src);
        fail(L"Не удалось создать временный файл пакета.");
        return 0;
    }

    unsigned char buffer[65536];
    uint64_t remaining = payload_len;
    int ok = 1;
    while (remaining > 0)
    {
        DWORD to_read = (DWORD)(remaining > sizeof(buffer) ? sizeof(buffer) : remaining);
        DWORD got = 0;
        if (!ReadFile(src, buffer, to_read, &got, NULL) || got == 0)
        {
            ok = 0;
            break;
        }
        DWORD written = 0;
        if (!WriteFile(dst, buffer, got, &written, NULL) || written != got)
        {
            ok = 0;
            break;
        }
        remaining -= got;
    }

    CloseHandle(src);
    CloseHandle(dst);

    if (!ok)
    {
        DeleteFileW(dest_path);
        fail(L"Не удалось скопировать пакет во временный файл.");
        return 0;
    }
    return 1;
}

// Синхронно запускает command_line и возвращает код завершения процесса, либо -1 при ошибке запуска.
static DWORD runAndWait(wchar_t* command_line, BOOL wait_for_exit, HANDLE* out_process)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessW(NULL, command_line, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        return (DWORD)-1;

    if (!wait_for_exit)
    {
        if (out_process)
            *out_process = pi.hProcess;
        else
            CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 0;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return exit_code;
}

// Заголовок окна локализован ("Aspia Host" / "Хост Aspia" / ...) — матчить по тексту нельзя.
// Отсеиваем по размеру: главное окно (host_window.ui, minimumSize 300x...) заведомо крупнее
// тултипов/всплывающих уведомлений, которые Qt-приложение может ненадолго показывать при старте
// помимо своего главного окна.
#define MIN_MAIN_WINDOW_WIDTH 150
#define MIN_MAIN_WINDOW_HEIGHT 100

// Матчим не по PID нашего собственного дочернего процесса, а по имени EXE-файла окна. Так надо
// из-за single-instance у Aspia Host (GuiApplication::isRunning(), lock-файл на основе session_id):
// если в этой же Windows-сессии уже открыт другой aspia_host.exe (например, оставшийся от
// предыдущего запуска), наш новый процесс просто активирует то, старое окно и сам почти сразу
// завершается — а слежка по PID тогда решила бы, что пользователь закрыл программу, хотя реальное
// окно всё это время оставалось открытым у другого процесса.
static BOOL isAspiaHostWindow(HWND hwnd)
{
    if (!IsWindowVisible(hwnd) || GetWindow(hwnd, GW_OWNER) != NULL)
        return FALSE;

    RECT r;
    if (!GetWindowRect(hwnd, &r))
        return FALSE;
    if ((r.right - r.left) < MIN_MAIN_WINDOW_WIDTH || (r.bottom - r.top) < MIN_MAIN_WINDOW_HEIGHT)
        return FALSE;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (!pid)
        return FALSE;

    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc)
        return FALSE;

    wchar_t image[MAX_PATH];
    DWORD size = MAX_PATH;
    BOOL ok = QueryFullProcessImageNameW(proc, 0, image, &size);
    CloseHandle(proc);
    if (!ok)
        return FALSE;

    wchar_t* name = wcsrchr(image, L'\\');
    name = name ? name + 1 : image;
    return lstrcmpiW(name, L"aspia_host.exe") == 0;
}

static BOOL CALLBACK enumWindowsProc(HWND hwnd, LPARAM lparam)
{
    HWND* result = (HWND*)lparam;
    if (!isAspiaHostWindow(hwnd))
        return TRUE;   // не то окно — продолжаем перечисление
    *result = hwnd;
    return FALSE;       // нашли главное окно — хватит
}

// Ищет главное окно Aspia Host (появляется не сразу после старта процесса, поэтому опрашиваем
// с таймаутом).
static HWND findMainWindow(DWORD timeout_ms)
{
    DWORD start = GetTickCount();
    for (;;)
    {
        HWND result = NULL;
        EnumWindows(enumWindowsProc, (LPARAM)&result);
        if (result)
            return result;
        if (GetTickCount() - start > timeout_ms)
            return NULL;
        Sleep(300);
    }
}

static BOOL CALLBACK anyWindowProc(HWND hwnd, LPARAM lparam)
{
    BOOL* found = (BOOL*)lparam;
    if (!isAspiaHostWindow(hwnd))
        return TRUE;
    *found = TRUE;
    return FALSE;
}

// Есть ли прямо сейчас хоть одно подходящее видимое окно Aspia Host — независимо от того, какой
// именно процесс его сейчас держит (см. isAspiaHostWindow).
static BOOL hasMainWindow(void)
{
    BOOL found = FALSE;
    EnumWindows(anyWindowProc, (LPARAM)&found);
    return found;
}

// Извне, без внедрения в чужой процесс, убирает кнопку сворачивания у окна Aspia Host — в
// Portable-сценарии это лишний промежуточный статус («спрятано, но не завершено»), нам нужны
// только «открыто» и «крестик = готово».
static void disableMinimizeBox(HWND hwnd)
{
    LONG_PTR style = GetWindowLongPtrW(hwnd, GWL_STYLE);
    SetWindowLongPtrW(hwnd, GWL_STYLE, style & ~WS_MINIMIZEBOX);
    SetWindowPos(hwnd, NULL, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR cmdline, int show)
{
    (void)hInstance; (void)hPrevInstance; (void)cmdline; (void)show;

    wchar_t temp_dir[MAX_PATH];
    wchar_t msi_path[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp_dir))
    {
        fail(L"Не удалось получить временный каталог.");
        return 1;
    }
    // Свой подкаталог, а не просто файл в %TEMP% — msiexec не должен споткнуться о занятое имя
    // при повторном запуске, да и подчищать за собой отдельный каталог надёжнее.
    wchar_t work_dir[MAX_PATH];
    wsprintfW(work_dir, L"%saspia_portable_%lu", temp_dir, GetCurrentProcessId());
    CreateDirectoryW(work_dir, NULL);
    wsprintfW(msi_path, L"%s\\package.msi", work_dir);

    if (!extractPayload(msi_path))
    {
        RemoveDirectoryW(work_dir);
        return 1;
    }

    // ---- 1. тихая установка ----
    // DESKTOP_SHORTCUT/STARTMENU_SHORTCUT — публичные MSI-свойства (Property-таблица пакета,
    // по умолчанию оба 1), от них условны компоненты DesktopShortcut/ProgramMenuShortcut.
    // Важно: условие в Component-таблице — это голое имя свойства ("DESKTOP_SHORTCUT"), а не
    // сравнение со значением. В MSI такое условие означает «свойство задано (не пусто)» —
    // DESKTOP_SHORTCUT=0 его ЗАДАЁТ (просто значением "0"), поэтому ярлык всё равно ставился.
    // Чтобы условие стало ложным, свойство нужно не задать нулём, а обнулить пустой строкой —
    // тогда msiexec трактует это как явную отмену дефолта из Property-таблицы.
    wchar_t cmd[MAX_PATH * 2];
    wsprintfW(cmd, L"msiexec.exe /i \"%s\" /quiet /norestart DESKTOP_SHORTCUT=\"\" STARTMENU_SHORTCUT=\"\"",
              msi_path);
    DWORD install_rc = runAndWait(cmd, TRUE, NULL);
    // 3010 = ERROR_SUCCESS_REBOOT_REQUIRED — тоже успех, просто просит перезагрузку.
    if (install_rc != 0 && install_rc != 3010)
    {
        wchar_t msg[256];
        wsprintfW(msg, L"Установка не удалась (код %lu). Возможно, отклонён запрос на права "
                  L"администратора.", install_rc);
        fail(msg);
        DeleteFileW(msi_path);
        RemoveDirectoryW(work_dir);
        return 1;
    }

    // ---- 2. запуск GUI хоста ----
    wchar_t program_files[MAX_PATH];
    // SHGetFolderPathW возвращает HRESULT: успех — это S_OK (0), а не "истина", поэтому
    // проверяем через FAILED(), а не через отрицание результата.
    HRESULT pf_hr = SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILES, NULL, SHGFP_TYPE_CURRENT, program_files);
    if (FAILED(pf_hr))
    {
        fail(L"Не удалось определить папку Program Files.");
        // всё равно попробуем снести то, что уже поставили
    }
    else
    {
        wchar_t host_exe[MAX_PATH];
        wsprintfW(host_exe, L"%s\\Aspia\\Host\\aspia_host.exe", program_files);

        wchar_t host_cmd[MAX_PATH + 4];
        wsprintfW(host_cmd, L"\"%s\"", host_exe);

        HANDLE host_process = NULL;
        if (runAndWait(host_cmd, FALSE, &host_process) == (DWORD)-1 || !host_process)
        {
            fail(L"Пакет установлен, но не удалось запустить Aspia Host — попробуйте открыть его "
                 L"вручную из меню Пуск.");
        }
        else
        {
            // Дальше нам нужен не сам процесс, а факт, что окно Aspia Host открыто — см. ниже,
            // почему слежка именно за ЭТИМ дочерним процессом ненадёжна.
            CloseHandle(host_process);

            HWND host_hwnd = findMainWindow(15000);
            if (host_hwnd)
                disableMinimizeBox(host_hwnd);

            // ---- 3. ждём сигнала «готово»: устойчивое отсутствие окна Aspia Host. Кнопки
            // свернуть нет, так что видимых состояний у окна остаётся два: открыто или закрыто —
            // без промежуточного «висит в трее», характерного для обычного использования
            // программы.
            //
            // Намеренно НЕ ждём завершения именно нашего дочернего процесса: у Aspia Host есть
            // single-instance (GuiApplication::isRunning(), lock-файл на основе session_id) — если
            // в этой же сессии Windows уже было открыто другое окно Aspia Host (например, забытое
            // с прошлого запуска), наш новый процесс просто активирует старое окно и сам сразу же
            // завершается, а окно при этом продолжает жить в другом, чужом процессе. Единственный
            // надёжный сигнал — сам факт отсутствия окна Aspia Host (isAspiaHostWindow, без
            // привязки к конкретному PID), причём устойчивый — несколько проверок подряд, а не
            // одна, чтобы не среагировать на случайное мигание видимости при перерисовке.
            int missing_polls = 0;
            const int required_missing_polls = 5;   // 5 * 300мс ≈ 1.5с устойчивого отсутствия
            for (;;)
            {
                Sleep(300);
                if (hasMainWindow())
                    missing_polls = 0;
                else if (++missing_polls >= required_missing_polls)
                    break;
            }
        }
    }

    // ---- 4. тихое удаление ----
    wsprintfW(cmd, L"msiexec.exe /x \"%s\" /quiet /norestart", msi_path);
    runAndWait(cmd, TRUE, NULL);

    // ---- 5. подчистка ProgramData ----
    // %ProgramData%\aspia (BasePaths::appConfigDir() в исходниках хоста) — не MSI-компонент,
    // программа создаёт этот каталог сама на лету (там лежит host.db3 — реальное хранилище
    // настроек), поэтому msiexec /x его не трогает. Без этого шага Portable оставляет за собой
    // самое важное — базу с пользователями и настройками.
    wchar_t common_appdata[MAX_PATH];
    HRESULT cad_hr = SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, common_appdata);
    if (SUCCEEDED(cad_hr))
    {
        wchar_t del_path[MAX_PATH + 16];
        ZeroMemory(del_path, sizeof(del_path));   // SHFileOperationW требует двойной \0 в конце списка
        wsprintfW(del_path, L"%s\\aspia", common_appdata);

        SHFILEOPSTRUCTW op;
        ZeroMemory(&op, sizeof(op));
        op.wFunc = FO_DELETE;
        op.pFrom = del_path;
        op.fFlags = FOF_NO_UI;   // без диалогов, без корзины — насовсем
        SHFileOperationW(&op);
    }

    // ---- 6. подчистка временного файла ----
    DeleteFileW(msi_path);
    RemoveDirectoryW(work_dir);

    return 0;
}
