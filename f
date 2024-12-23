#include <windows.h>
#include <gdiplus.h>
#include <wininet.h>
#include <string>
#include <vector>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <locale>
#include <codecvt>
#include <windowsx.h>
#include <mmsystem.h> // Для PlaySound
#include <CommCtrl.h> // Для общих контролов
#include <richedit.h> // Для Rich Edit контролов
#include "resource.h" // Убедитесь, что у вас есть этот заголовочный файл для идентификаторов ресурсов

#define IDR_WAVE1 101
#define IDR_WAVE2 102
#define IDR_WAVE3 103
#define IDR_WAVE4 104

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "winmm.lib") // Линковка с winmm.lib для PlaySound
#pragma comment(lib, "comctl32.lib") // Линковка с comctl32.lib для общих контролов

using namespace Gdiplus;

// Структура для хранения информации об изображении
struct ImageItem {
    Image* image;
    std::wstring title;
    float x; // Координата X на экране
    float y; // Координата Y на экране
    float width; // Ширина отображаемого изображения
    float height; // Высота отображаемого изображения
};

// Глобальные переменные
Image* backgroundImage = nullptr;
Image* wifiIcon = nullptr;
Image* soundIcon = nullptr;
Image* batteryIcon = nullptr;
Image* mypassIcon = nullptr; // Иконка меню Пуск
Image* additionalIcon = nullptr; // Новая иконка перед временем

// Список языков
std::vector<std::wstring> languages = { L"РУС", L"ENG" }; // Русский и Английский
int currentLanguageIndex = 0; // Текущий индекс языка

// Список дополнительных изображений
std::vector<ImageItem> images;

// Функция для загрузки изображения из URL
bool LoadImageFromURL(const std::wstring& url, Image*& outImage) {
    HINTERNET hInternet = InternetOpen(L"ImageLoader", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        OutputDebugString(L"InternetOpen не удалось\n");
        return false;
    }

    // Флаги для открытия URL: без кеша и чтение данных по мере загрузки
    HINTERNET hConnect = InternetOpenUrl(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE, 0);
    if (!hConnect) {
        OutputDebugString(L"InternetOpenUrl не удалось\n");
        InternetCloseHandle(hInternet);
        return false;
    }

    // Чтение всех данных
    std::vector<BYTE> buffer;
    DWORD bytesAvailable = 0;
    DWORD bytesRead = 0;
    BYTE tempBuffer[4096];
    while (InternetQueryDataAvailable(hConnect, &bytesAvailable, 0, 0) && bytesAvailable > 0) {
        DWORD toRead = min(bytesAvailable, (DWORD)sizeof(tempBuffer));
        if (InternetReadFile(hConnect, tempBuffer, toRead, &bytesRead) && bytesRead > 0) {
            buffer.insert(buffer.end(), tempBuffer, tempBuffer + bytesRead);
        }
        else {
            break;
        }
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    if (buffer.empty()) {
        OutputDebugString(L"Нет данных, загруженных из URL\n");
        return false;
    }

    // Создание потока из буфера
    IStream* stream = nullptr;
    if (FAILED(CreateStreamOnHGlobal(NULL, TRUE, &stream))) {
        OutputDebugString(L"CreateStreamOnHGlobal не удалось\n");
        return false;
    }

    ULONG written;
    // **Исправлено Предупреждение C4267**: Явное приведение buffer.size() к ULONG
    if (FAILED(stream->Write(buffer.data(), static_cast<ULONG>(buffer.size()), &written)) || written != static_cast<ULONG>(buffer.size())) {
        OutputDebugString(L"Запись в поток не удалась\n");
        stream->Release();
        return false;
    }

    LARGE_INTEGER liZero = {};
    stream->Seek(liZero, STREAM_SEEK_SET, NULL);

    // Загрузка изображения из потока
    Image* img = new Image(stream);
    stream->Release();

    // Проверка статуса загрузки изображения
    if (img->GetLastStatus() != Ok) {
        OutputDebugString(L"Не удалось создать Image из потока\n");
        delete img;
        return false;
    }

    outImage = img;
    OutputDebugString(L"Изображение успешно загружено\n");
    return true;
}

// Функция для получения текущего времени в виде строки
std::wstring GetCurrentTimeString() {
    using namespace std::chrono;
    auto now = system_clock::now();
    std::time_t now_c = system_clock::to_time_t(now);
    std::tm parts;

    // Используем localtime_s для потокобезопасности
    localtime_s(&parts, &now_c);

    std::wstringstream ss;
    ss << std::put_time(&parts, L"%H:%M"); // Формат времени ЧЧ:ММ
    return ss.str();
}

// Функция для воспроизведения звука
void PlaySoundByLanguage(const std::wstring& soundName) {
    // Определите пути к звуковым файлам или используйте системные звуки
    // Для демонстрации будем использовать системные звуки на основе soundName
    // Вы можете заменить это на фактические пути к файлам или URL

    std::wstring soundPath;
    if (currentLanguageIndex == 0) { // Русский
        if (soundName == L"WindowsLogo") {
            // Воспроизведение системного звука или указание пользовательского пути
            // Пример: PlaySound(L"C:\\Sounds\\windows_logo.wav", NULL, SND_FILENAME | SND_ASYNC);
            PlaySound(MAKEINTRESOURCE(IDR_WAVE1), NULL, SND_RESOURCE | SND_ASYNC);
        }
        else if (soundName == L"WiFi") {
            PlaySound(MAKEINTRESOURCE(IDR_WAVE2), NULL, SND_RESOURCE | SND_ASYNC);
        }
        else if (soundName == L"BatteryCharging") {
            PlaySound(MAKEINTRESOURCE(IDR_WAVE3), NULL, SND_RESOURCE | SND_ASYNC);
        }
        else if (soundName == L"Triangle") {
            PlaySound(MAKEINTRESOURCE(IDR_WAVE4), NULL, SND_RESOURCE | SND_ASYNC);
        }
    }
    else { // Английский или другие языки
        // Опционально, воспроизводите разные звуки или не воспроизводите звуки
    }
}

// Функция для инициализации дополнительных изображений
bool InitializeImages() {
    // Список URL изображений и соответствующих заголовков
    std::vector<std::pair<std::wstring, std::wstring>> imageData = {
        { L"https://i.postimg.cc/4x8HknSh/nyc01-temp-32d4-T5s3-TEIMt1-R3qrjho.png", L"Новая папка" }, // Новая папка
        { L"https://i.postimg.cc/0Q12Jw0R/fra01-temp-r-MINe9-WDa-DPi-KQl-Rb3p-F-processed.png", L"Этот компьютер" }, // Этот компьютер
        // Добавьте больше изображений по необходимости
    };

    // Начальные позиции для изображений
    float startX = 50.0f;
    float startY = 150.0f; // Расположены ниже объявления
    float spacing = 150.0f; // Уменьшено расстояние для лучшего макета

    for (size_t i = 0; i < imageData.size(); ++i) {
        Image* img = nullptr;
        if (LoadImageFromURL(imageData[i].first, img)) {
            ImageItem item;
            item.image = img;
            item.title = imageData[i].second;
            item.x = startX + i * spacing; // Позиция по оси X с учетом расстояния
            item.y = startY; // Фиксированная позиция по оси Y
            item.width = 100.0f; // Ширина изображения
            item.height = 100.0f; // Высота изображения
            images.push_back(item);
        }
        else {
            OutputDebugString((L"Не удалось загрузить изображение: " + imageData[i].first + L"\n").c_str());
            return false;
        }
    }

    // Загрузка иконок Wi-Fi, Звука, Батареи и меню Пуск
    struct IconData {
        Image** imagePtr;
        std::wstring url;
    };

    std::vector<IconData> iconsToLoad = {
        { &wifiIcon, L"https://upload.wikimedia.org/wikipedia/commons/thumb/7/74/Feather-core-wifi.svg/1200px-Feather-core-wifi.svg.png" },
        { &soundIcon, L"https://cdn-icons-png.flaticon.com/512/84/84922.png" },
        { &batteryIcon, L"https://i.postimg.cc/1RFQP7JK/Remove-bg-ai-1729799941732.png" },
        { &mypassIcon, L"https://i.postimg.cc/4NdmpG5m/fra01-temp-p5-FXAe-Zabapcdd-X5k-Pb0-R-1.png" }, // Иконка меню Пуск
    };

    for (const auto& icon : iconsToLoad) {
        if (!LoadImageFromURL(icon.url, *(icon.imagePtr))) {
            OutputDebugString((L"Не удалось загрузить иконку: " + icon.url + L"\n").c_str());
            return false;
        }
    }

    // Загрузка дополнительной иконки перед временем
    // Замените URL на нужный вам
    if (!LoadImageFromURL(L"https://example.com/path-to-your-additional-image.png", additionalIcon)) {
        OutputDebugString(L"Не удалось загрузить дополнительную иконку.\n");
        // В зависимости от требований вы можете решить, является ли это критичной ошибкой
        // Для продолжения работы можно не возвращать false
    }

    return true;
}

// Структура для хранения данных окна
struct WindowData {
    bool isDragging = false;
    size_t draggingImageIndex = SIZE_MAX; // Недопустимый индекс изначально
    POINT lastMousePos = { 0, 0 };

    // Состояние редактирования
    size_t editingImageIndex = SIZE_MAX; // Индекс редактируемого изображения
    HWND editControl = NULL; // Дескриптор текущего контрола редактирования
    bool isCreatingFolder = false; // Флаг для создания папки
};

// Функция для создания контекстного меню
void CreateContextMenu(HWND hwnd, int x, int y, size_t imageIndex, bool isOnImage) {
    HMENU hMenu = CreatePopupMenu();
    if (hMenu) {
        if (isOnImage && imageIndex < images.size()) {
            // Контекстное меню для изображений
            AppendMenu(hMenu, MF_STRING, 1, L"Открыть");       // Open
            AppendMenu(hMenu, MF_STRING, 2, L"Переименовать"); // Rename
            AppendMenu(hMenu, MF_STRING, 3, L"Удалить");       // Delete
        }
        else {
            // Контекстное меню для пустого пространства
            AppendMenu(hMenu, MF_STRING, 4, L"Создать папку"); // Create Folder
        }

        // Установить окно на передний план для корректного закрытия меню
        SetForegroundWindow(hwnd);

        // Отследить появившееся меню
        int cmd = TrackPopupMenu(
            hMenu,
            TPM_RETURNCMD | TPM_TOPALIGN | TPM_LEFTALIGN,
            x,
            y,
            0,
            hwnd,
            NULL
        );

        // Обработка выбора меню
        if (isOnImage && imageIndex < images.size()) {
            if (cmd == 1) { // Open
                MessageBox(hwnd, (images[imageIndex].title + L" открыта.").c_str(), L"Открыть", MB_OK);
            }
            else if (cmd == 2) { // Rename
                // Инициация переименования путём создания контрола Edit
                WindowData* data = reinterpret_cast<WindowData*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
                if (data && data->editControl == NULL) {
                    data->editingImageIndex = imageIndex;

                    // Вычисление позиции для контрола Edit
                    float titleWidth = 100.0f; // Приблизительная ширина
                    Gdiplus::RectF titleRect;
                    HDC hdc = GetDC(hwnd);
                    Graphics graphics(hdc);
                    FontFamily fontFamily(L"Segoe UI");
                    Font font(&fontFamily, 16, FontStyleRegular, UnitPixel);
                    SolidBrush brush(Color(255, 255, 255, 255)); // Белый цвет текста
                    graphics.MeasureString(images[imageIndex].title.c_str(), -1, &font, PointF(0, 0), &titleRect);
                    ReleaseDC(hwnd, hdc);

                    float editX = images[imageIndex].x;
                    float editY = images[imageIndex].y + images[imageIndex].height + 5.0f;
                    float editWidth = titleRect.Width + 10.0f; // Небольшие отступы
                    float editHeight = titleRect.Height + 5.0f;

                    HWND hwndEdit = CreateWindowEx(
                        0,
                        L"EDIT",
                        images[imageIndex].title.c_str(),
                        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                        static_cast<int>(editX),
                        static_cast<int>(editY),
                        static_cast<int>(editWidth),
                        static_cast<int>(editHeight),
                        hwnd,
                        NULL,
                        GetModuleHandle(NULL),
                        NULL
                    );

                    if (hwndEdit) {
                        data->editControl = hwndEdit;
                        // Установка фокуса на контрол редактирования
                        SetFocus(hwndEdit);
                    }
                }
            }
            else if (cmd == 3) { // Delete
                // Реализуйте удаление по необходимости
                MessageBox(hwnd, L"Функция удаления не реализована.", L"Удалить", MB_OK);
            }
        }
        else {
            if (cmd == 4) { // Create Folder
                // Инициация создания папки путём добавления нового ImageItem и создания контрола Edit
                WindowData* data = reinterpret_cast<WindowData*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
                if (data && data->editControl == NULL) {
                    ImageItem newItem;
                    // Вы можете установить URL значка папки или использовать локальный ресурс
                    if (LoadImageFromURL(L"https://i.postimg.cc/4x8HknSh/nyc01-temp-32d4-T5s3-TEIMt1-R3qrjho.png", newItem.image)) {
                        newItem.title = L"Новая папка"; // Имя по умолчанию
                        // Позиционирование новой папки там, где пользователь щёлкнул правой кнопкой мыши
                        newItem.x = static_cast<float>(x);
                        newItem.y = static_cast<float>(y);
                        newItem.width = 100.0f;
                        newItem.height = 100.0f;
                        images.push_back(newItem);
                        size_t newIndex = images.size() - 1;
                        data->editingImageIndex = newIndex;
                        data->isCreatingFolder = true;

                        // Создание контрола Edit для новой папки
                        HWND hwndEdit = CreateWindowEx(
                            0,
                            L"EDIT",
                            newItem.title.c_str(),
                            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                            static_cast<int>(newItem.x),
                            static_cast<int>(newItem.y + newItem.height + 5.0f),
                            100,
                            25,
                            hwnd,
                            NULL,
                            GetModuleHandle(NULL),
                            NULL
                        );

                        if (hwndEdit) {
                            data->editControl = hwndEdit;
                            // Установка фокуса на контрол редактирования
                            SetFocus(hwndEdit);
                        }
                    }
                    else {
                        MessageBox(hwnd, L"Не удалось загрузить иконку папки.", L"Ошибка", MB_ICONERROR);
                    }
                }
            }
        }

        DestroyMenu(hMenu);
    }
}

// Процедура окна
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    // Получение данных окна
    WindowData* data = reinterpret_cast<WindowData*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));

    switch (uMsg) {
    case WM_CREATE: {
        // Выделение и сохранение данных окна
        WindowData* wndData = new WindowData();
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(wndData));
        return 0;
    }

    case WM_DESTROY:
        // Очистка данных окна
        if (data) {
            delete data;
        }

        // Удаление загруженных изображений
        delete backgroundImage;
        delete wifiIcon;
        delete soundIcon;
        delete batteryIcon;
        delete mypassIcon; // Очистка иконки меню Пуск
        delete additionalIcon; // Очистка новой иконки
        for (auto& imgItem : images) {
            delete imgItem.image;
        }
        PostQuitMessage(0);
        return 0;

    case WM_KEYDOWN:
        // Проверка нажатия клавиши Esc для закрытия окна
        if (wParam == VK_ESCAPE) {
            DestroyWindow(hwnd); // Закрыть окно
        }

        // Обработка переключения языка через Alt+Shift или Win+Space
        if (((GetAsyncKeyState(VK_MENU) & 0x8000) && wParam == VK_SHIFT) ||
            ((GetAsyncKeyState(VK_LWIN) & 0x8000) && wParam == VK_SPACE)) {
            currentLanguageIndex = (currentLanguageIndex + 1) % languages.size(); // Переключение языка
            InvalidateRect(hwnd, NULL, TRUE); // Перерисовать окно

            // Воспроизведение звуков, если язык Русский
            if (languages[currentLanguageIndex] == L"РУС") {
                PlaySoundByLanguage(L"WindowsLogo");
                PlaySoundByLanguage(L"WiFi");
                PlaySoundByLanguage(L"BatteryCharging");
                PlaySoundByLanguage(L"Triangle");
            }
        }

        return 0;

    case WM_SIZE: {
        InvalidateRect(hwnd, NULL, TRUE); // Перерисовать окно при изменении размера
        return 0;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        Graphics graphics(hdc);

        // Установка высококачественных настроек рендеринга
        graphics.SetSmoothingMode(SmoothingModeHighQuality);
        graphics.SetInterpolationMode(InterpolationModeHighQualityBicubic);
        graphics.SetPixelOffsetMode(PixelOffsetModeHighQuality);

        // Получение размеров окна
        RECT windowRect;
        GetClientRect(hwnd, &windowRect);

        // Рисование фонового изображения с сохранением соотношения сторон
        if (backgroundImage) {
            UINT imgWidth = backgroundImage->GetWidth();
            UINT imgHeight = backgroundImage->GetHeight();

            double windowAspect = static_cast<double>(windowRect.right) / windowRect.bottom;
            double imageAspect = static_cast<double>(imgWidth) / imgHeight;

            double drawWidth, drawHeight;
            if (windowAspect > imageAspect) {
                // Окно шире изображения
                drawHeight = windowRect.bottom;
                drawWidth = imageAspect * drawHeight;
            }
            else {
                // Окно уже или равно изображению
                drawWidth = windowRect.right;
                drawHeight = drawWidth / imageAspect;
            }

            float x = static_cast<float>((windowRect.right - drawWidth) / 2.0);
            float y = static_cast<float>((windowRect.bottom - drawHeight) / 2.0);
            graphics.DrawImage(backgroundImage, x, y, static_cast<REAL>(drawWidth), static_cast<REAL>(drawHeight));
        }

        // Рисование нижней панели
        RECT panelRect = { 0, windowRect.bottom - 40, windowRect.right, windowRect.bottom };
        FillRect(hdc, &panelRect, (HBRUSH)(COLOR_BTNFACE + 1)); // Цвет панели

        // Рисование иконки меню Пуск слева
        if (mypassIcon) {
            float iconSize = 42.0f; // Размер иконки
            float iconY = static_cast<float>(windowRect.bottom - 40 + (40 - iconSize) / 2.0); // Вертикальное центрирование

            float padding = 15.0f;
            float startMenuX = padding;

            graphics.DrawImage(mypassIcon, startMenuX, iconY, iconSize, iconSize);
        }

        // Рисование иконок Wi-Fi, Звука и Батареи справа горизонтально
        if (wifiIcon && soundIcon && batteryIcon) {
            float iconSize = 20.0f; // Размер иконки
            float iconPadding = 10.0f; // Отступ между иконками

            // Фиксированная координата Y для всех иконок (вертикальное центрирование в нижней панели)
            float panelHeight = 40.0f;
            float iconY = static_cast<float>(windowRect.bottom - panelHeight + (panelHeight - iconSize) / 2.0f);

            // Начальная координата X для самой правой иконки (Батарея)
            float paddingRight = 145.0f; // Отступ от правого края
            float iconX = static_cast<float>(windowRect.right - paddingRight - iconSize);

            // Рисование иконки Батареи (самая правая)
            graphics.DrawImage(batteryIcon, iconX, iconY, iconSize, iconSize);

            // Рисование иконки Звука слева от Батареи
            iconX -= (iconSize + iconPadding);
            graphics.DrawImage(soundIcon, iconX, iconY, iconSize, iconSize);

            // Рисование иконки Wi-Fi слева от Звука
            iconX -= (iconSize + iconPadding);
            graphics.DrawImage(wifiIcon, iconX, iconY, iconSize, iconSize);
        }

        // Рисование дополнительной иконки перед временем
        if (additionalIcon) {
            float addIconSize = 20.0f; // Размер дополнительной иконки
            float addIconPadding = 5.0f; // Отступ между иконкой и временем

            // Получение текущего времени и языка
            std::wstring timeString = GetCurrentTimeString();
            std::wstring langString = languages[currentLanguageIndex]; // Текущий язык

            // Использование GDI+ для измерения размера текста
            FontFamily fontFamilyObj(L"Segoe UI"); // Выбор шрифта
            Font font(&fontFamilyObj, 14, FontStyleRegular, UnitPixel); // Размер шрифта

            RectF timeRect;
            graphics.MeasureString(timeString.c_str(), -1, &font, PointF(0, 0), &timeRect);
            RectF langRect;
            graphics.MeasureString(langString.c_str(), -1, &font, PointF(0, 0), &langRect);

            // Вычисление позиции для текста
            float paddingText = 15.0f;
            float xTime = static_cast<float>(windowRect.right - timeRect.Width - langRect.Width - 70); // Right margin
            float yText = static_cast<float>(windowRect.bottom - 40 + (40 - timeRect.Height) / 2.0f - 1); // Vertical align

            // Вычисление позиции для дополнительной иконки
            float iconYPos = yText - (addIconSize - font.GetHeight() / 2.0f) / 2.0f; // Центрирование иконки относительно текста
            float iconXPos = xTime - (addIconSize + addIconPadding); // Расположение слева от времени

            // Рисование дополнительной иконки
            graphics.DrawImage(additionalIcon, iconXPos, iconYPos, addIconSize, addIconSize);
        }

        // Получение текущего времени
        std::wstring timeStringFinal = GetCurrentTimeString();
        std::wstring langStringFinal = languages[currentLanguageIndex]; // Текущий язык

        // Использование GDI+ для рисования текста
        FontFamily fontFamilyObjFinal(L"Segoe UI"); // Выбор шрифта
        Font fontFinal(&fontFamilyObjFinal, 14, FontStyleRegular, UnitPixel); // Размер шрифта
        SolidBrush brush(Color(255, 0, 0, 0)); // Черный цвет текста

        // Измерение размеров текста
        RectF timeRectFinal;
        graphics.MeasureString(timeStringFinal.c_str(), -1, &fontFinal, PointF(0, 0), &timeRectFinal);
        RectF langRectFinal;
        graphics.MeasureString(langStringFinal.c_str(), -1, &fontFinal, PointF(0, 0), &langRectFinal);

        // Вычисление позиций для текста
        float paddingTextFinal = 15.0f;
        float xTimePos = static_cast<float>(windowRect.right - timeRectFinal.Width - langRectFinal.Width - 70); // Правый отступ
        float yTextPos = static_cast<float>(windowRect.bottom - 40 + (40 - timeRectFinal.Height) / 2.0f - 1); // Вертикальное выравнивание

        // Рисование текущего языка
        PointF langPointFinal(xTimePos, yTextPos);
        graphics.DrawString(langStringFinal.c_str(), -1, &fontFinal, langPointFinal, &brush);

        // Рисование текущего времени справа от языка
        PointF timePointFinal(xTimePos + langRectFinal.Width + 10.0f, yTextPos); // Отступ между языком и временем
        graphics.DrawString(timeStringFinal.c_str(), -1, &fontFinal, timePointFinal, &brush);

        // Добавление объявления ОС в центре экрана
        std::wstring announcement;
        if (languages[currentLanguageIndex] == L"РУС") {
            announcement = L"Представляем Orega OS: Будущее Производительности!";
        }
        else {
            announcement = L"Introducing Orega OS: The Future of Performance!";
        }
        RectF announcementRect;
        Font largeFont(&fontFamilyObjFinal, 40, FontStyleBold, UnitPixel); // Шрифт для объявления
        graphics.MeasureString(announcement.c_str(), -1, &largeFont, PointF(0, 0), &announcementRect);

        // Позиционирование объявления в центре
        float xAnnouncement = (static_cast<float>(windowRect.right) - announcementRect.Width) / 2.0f;
        float yAnnouncement = (static_cast<float>(windowRect.bottom) - announcementRect.Height) / 2.0f;
        PointF announcementPoint(xAnnouncement, yAnnouncement);

        SolidBrush announcementBrush(Color(255, 255, 255, 255)); // Белый цвет текста для объявления
        graphics.DrawString(announcement.c_str(), -1, &largeFont, announcementPoint, &announcementBrush);

        // Рисование дополнительных изображений и их заголовков
        for (const auto& imgItem : images) {
            // Рисование изображения
            graphics.DrawImage(imgItem.image, imgItem.x, imgItem.y, imgItem.width, imgItem.height);

            // Рисование заголовка под изображением, центрировано
            Font titleFont(&fontFamilyObjFinal, 16, FontStyleRegular, UnitPixel);
            SolidBrush titleBrush(Color(255, 255, 255, 255)); // Белый цвет текста для заголовков

            RectF titleRect;
            graphics.MeasureString(imgItem.title.c_str(), -1, &titleFont, PointF(0, 0), &titleRect);

            float xTitle = imgItem.x + (imgItem.width - titleRect.Width) / 2.0f;
            float yTitle = imgItem.y + imgItem.height + 5.0f; // Отступ под изображением

            PointF titlePoint(xTitle, yTitle);
            graphics.DrawString(imgItem.title.c_str(), -1, &titleFont, titlePoint, &titleBrush);
        }

        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_LBUTTONDOWN: {
        if (data) {
            // Получение позиции мыши
            int mouseX = GET_X_LPARAM(lParam);
            int mouseY = GET_Y_LPARAM(lParam);
            POINT mousePt = { mouseX, mouseY };

            // Получение размеров окна
            RECT windowRect;
            GetClientRect(hwnd, &windowRect);

            // Проверка, находится ли клик на кнопке меню Пуск
            bool isOnStartMenu = false;
            RECT startMenuRect = {
                15,
                static_cast<LONG>(windowRect.bottom - 40 + (40 - 42.0f) / 2),
                15 + 42,
                static_cast<LONG>(windowRect.bottom - 40 + (40 - 42.0f) / 2 + 42)
            };
            if (PtInRect(&startMenuRect, mousePt)) {
                isOnStartMenu = true;
                // Обработка клика по меню Пуск
                MessageBox(hwnd, L"Меню Пуск нажато!", L"Меню Пуск", MB_OK);
                return 0;
            }

            // Проверка кликов по системным иконкам (Wi-Fi, Звук, Батарея)
            std::vector<Image*> systemIcons = { wifiIcon, soundIcon, batteryIcon };
            float iconSize = 20.0f;
            float iconPadding = 10.0f;
            float paddingRight = 145.0f;
            float totalWidth = (iconSize * systemIcons.size()) + (iconPadding * (systemIcons.size() - 1));
            float iconXStart = static_cast<float>(windowRect.right - paddingRight - totalWidth);
            float iconY = static_cast<float>(windowRect.bottom - 40 + (40 - iconSize) / 2.0f);

            for (size_t i = 0; i < systemIcons.size(); ++i) {
                RECT iconRect = {
                    static_cast<LONG>(iconXStart + i * (iconSize + iconPadding)),
                    static_cast<LONG>(iconY),
                    static_cast<LONG>(iconXStart + i * (iconSize + iconPadding) + iconSize),
                    static_cast<LONG>(iconY + iconSize)
                };
                if (PtInRect(&iconRect, mousePt)) {
                    // Обработка клика по соответствующей иконке
                    if (i == 0) { // Wi-Fi
                        MessageBox(hwnd, L"Wi-Fi иконка нажата!", L"Wi-Fi", MB_OK);
                    }
                    else if (i == 1) { // Звук
                        MessageBox(hwnd, L"Звуковая иконка нажата!", L"Звук", MB_OK);
                    }
                    else if (i == 2) { // Батарея
                        MessageBox(hwnd, L"Батарейная иконка нажата!", L"Батарея", MB_OK);
                    }
                    break;
                }
            }

            // Проверка кликов по дополнительной иконке
            if (additionalIcon) {
                float addIconSize = 20.0f; // Размер дополнительной иконки
                float addIconPadding = 5.0f; // Отступ между иконкой и временем

                // Получение текущего времени и языка
                std::wstring timeString = GetCurrentTimeString();
                std::wstring langString = languages[currentLanguageIndex]; // Текущий язык

                // Использование GDI+ для измерения размера текста
                FontFamily fontFamilyObj(L"Segoe UI"); // Выбор шрифта
                Font font(&fontFamilyObj, 14, FontStyleRegular, UnitPixel); // Размер шрифта

                RectF timeRect;
                Graphics graphicsSample(NULL, NULL); // Создание временного объекта Graphics для измерения
                graphicsSample.MeasureString(timeString.c_str(), -1, &font, PointF(0, 0), &timeRect);
                RectF langRect;
                graphicsSample.MeasureString(langString.c_str(), -1, &font, PointF(0, 0), &langRect);

                // Вычисление позиции для дополнительной иконки
                float iconXPos = static_cast<float>(windowRect.right) - 70.0f - langRect.Width - timeRect.Width - addIconPadding - addIconSize;
                float iconYPos = static_cast<float>(windowRect.bottom - 40 + (40 - addIconSize) / 2.0f);

                RECT additionalIconRect = {
                    static_cast<LONG>(iconXPos),
                    static_cast<LONG>(iconYPos),
                    static_cast<LONG>(iconXPos + addIconSize),
                    static_cast<LONG>(iconYPos + addIconSize)
                };

                if (PtInRect(&additionalIconRect, mousePt)) {
                    // Обработка клика по дополнительной иконке
                    MessageBox(hwnd, L"Дополнительная иконка нажата!", L"Дополнительная Иконка", MB_OK);
                    return 0;
                }
            }

            // Проверка, находится ли клик на каком-либо изображении (сверху вниз)
            for (size_t i = images.size(); i-- > 0;) {
                const auto& imgItem = images[i];
                RECT imgRect = {
                    static_cast<LONG>(imgItem.x),
                    static_cast<LONG>(imgItem.y),
                    static_cast<LONG>(imgItem.x + imgItem.width),
                    static_cast<LONG>(imgItem.y + imgItem.height)
                };
                if (PtInRect(&imgRect, mousePt)) {
                    // Начало перетаскивания
                    data->isDragging = true;
                    data->draggingImageIndex = i;
                    data->lastMousePos = mousePt;

                    // Захват мыши
                    SetCapture(hwnd);

                    // Поднять перетаскиваемое изображение наверх
                    ImageItem draggedItem = images[i];
                    images.erase(images.begin() + i);
                    images.push_back(draggedItem);
                    data->draggingImageIndex = images.size() - 1;

                    InvalidateRect(hwnd, NULL, TRUE);
                    break;
                }
            }
        }
        return 0;
    }

    case WM_RBUTTONDOWN: {
        // Обработка правых кликов для контекстных меню
        if (data) {
            // Получение позиции мыши
            int mouseX = GET_X_LPARAM(lParam);
            int mouseY = GET_Y_LPARAM(lParam);
            POINT mousePt = { mouseX, mouseY };

            // Проверка, находится ли клик на каком-либо изображении
            bool isOnImage = false;
            size_t imageIndex = SIZE_MAX;
            for (size_t i = 0; i < images.size(); ++i) {
                const auto& imgItem = images[i];
                RECT imgRect = {
                    static_cast<LONG>(imgItem.x),
                    static_cast<LONG>(imgItem.y),
                    static_cast<LONG>(imgItem.x + imgItem.width),
                    static_cast<LONG>(imgItem.y + imgItem.height)
                };
                if (PtInRect(&imgRect, mousePt)) {
                    isOnImage = true;
                    imageIndex = i;
                    break;
                }
            }

            // Создание и отображение контекстного меню
            CreateContextMenu(hwnd, mouseX, mouseY, imageIndex, isOnImage);
        }
        return 0;
    }

    case WM_MOUSEMOVE: {
        if (data && data->isDragging && data->draggingImageIndex < images.size()) {
            // Получение текущей позиции мыши
            int mouseX = GET_X_LPARAM(lParam);
            int mouseY = GET_Y_LPARAM(lParam);
            POINT currentPt = { mouseX, mouseY };

            // Вычисление дельты движения
            int deltaX = currentPt.x - data->lastMousePos.x;
            int deltaY = currentPt.y - data->lastMousePos.y;

            if (deltaX != 0 || deltaY != 0) {
                // Обновление позиции изображения
                images[data->draggingImageIndex].x += static_cast<float>(deltaX);
                images[data->draggingImageIndex].y += static_cast<float>(deltaY);

                // Получение размеров окна
                RECT windowRect;
                GetClientRect(hwnd, &windowRect);

                // Обеспечение того, чтобы изображение осталось внутри границ окна
                if (images[data->draggingImageIndex].x < 0)
                    images[data->draggingImageIndex].x = 0;
                if (images[data->draggingImageIndex].y < 0)
                    images[data->draggingImageIndex].y = 0;
                if (images[data->draggingImageIndex].x +
                    images[data->draggingImageIndex].width > windowRect.right)
                    images[data->draggingImageIndex].x = windowRect.right - images[data->draggingImageIndex].width;
                if (images[data->draggingImageIndex].y + images[data->draggingImageIndex].height > windowRect.bottom - 40) // 40 для панели
                    images[data->draggingImageIndex].y = windowRect.bottom - 40 - images[data->draggingImageIndex].height;

                // Обновление последней позиции мыши
                data->lastMousePos = currentPt;

                // Перерисовка окна
                InvalidateRect(hwnd, NULL, TRUE);
            }
        }
        return 0;
    }

    case WM_LBUTTONUP: {
        if (data) {
            // Отпускание захвата мыши
            ReleaseCapture();

            if (data->isDragging && data->draggingImageIndex < images.size()) {
                // Определение, был ли это клик или перетаскивание на основе движения
                // Для простоты считаем это кликом, если позиция не сильно изменилась
                // Для более надежного различения клика и перетаскивания можно добавить более точные проверки

                // Проверка, если ли мышь близко к последней позиции
                int mouseX = GET_X_LPARAM(lParam);
                int mouseY = GET_Y_LPARAM(lParam);
                POINT currentPt = { mouseX, mouseY };
                int distance = abs(currentPt.x - data->lastMousePos.x) + abs(currentPt.y - data->lastMousePos.y);

                if (distance < 5) { // Порог для клика
                    // Это клик, а не перетаскивание
                    CreateContextMenu(hwnd, mouseX, mouseY, data->draggingImageIndex, true);
                }

                // Остановка перетаскивания
                data->isDragging = false;
                data->draggingImageIndex = SIZE_MAX;
            }
        }
        return 0;
    }

    case WM_COMMAND: {
        if (HIWORD(wParam) == EN_KILLFOCUS && LOWORD(wParam) == 0) {
            // Контрол Edit потерял фокус
            if (data && data->editControl) {
                std::wstring newText(256, L'\0');
                GetWindowText(data->editControl, &newText[0], 256);
                newText.resize(wcslen(newText.c_str()));

                if (data->isCreatingFolder && data->editingImageIndex < images.size()) {
                    // Обновление заголовка для новой папки
                    images[data->editingImageIndex].title = newText;
                    data->isCreatingFolder = false;
                }
                else if (data->editingImageIndex < images.size()) {
                    // Обновление заголовка существующей папки
                    images[data->editingImageIndex].title = newText;
                }

                // Удаление контрола Edit
                DestroyWindow(data->editControl);
                data->editControl = NULL;
                data->editingImageIndex = SIZE_MAX;

                // Перерисовка окна для отображения обновленного заголовка
                InvalidateRect(hwnd, NULL, TRUE);
            }
        }
        else if (HIWORD(wParam) == EN_UPDATE && lParam != 0) {
            // Обработка нажатия Enter в контроле Edit
            HWND hwndEdit = reinterpret_cast<HWND>(lParam);
            if (data && data->editControl == hwndEdit) {
                if (GetKeyState(VK_RETURN) & 0x8000) {
                    // Симуляция потери фокуса для подтверждения редактирования
                    SendMessage(hwndEdit, WM_KILLFOCUS, 0, 0);
                }
            }
        }
        return 0;
    }

    case WM_NOTIFY: {
        // Обработка уведомлений, если необходимо
        return 0;
    }

    default:
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
}

// Основная функция приложения
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    const wchar_t CLASS_NAME[] = L"FullscreenWindowClass";

    // Инициализация GDI+
    GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    if (GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL) != Ok) {
        MessageBox(NULL, L"Не удалось инициализировать GDI+", L"Ошибка", MB_ICONERROR);
        return 0;
    }

    // Определение класса окна
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    if (!RegisterClass(&wc)) {
        MessageBox(NULL, L"Не удалось зарегистрировать класс окна.", L"Ошибка", MB_ICONERROR);
        GdiplusShutdown(gdiplusToken);
        return 0;
    }

    // Инициализация общих контролов (опционально, для функциональности диалогов)
    INITCOMMONCONTROLSEX icex = { sizeof(INITCOMMONCONTROLSEX), ICC_WIN95_CLASSES };
    InitCommonControlsEx(&icex);

    // Получение размеров экрана
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    // Создание окна
    HWND hwnd = CreateWindowEx(
        WS_EX_TOPMOST, // Окно всегда поверх других
        CLASS_NAME,
        L"Orega OS Presentation",
        WS_POPUP, // Убираем границы окна
        0, 0, screenWidth, screenHeight, // Позиция и размер окна
        NULL,
        NULL,
        hInstance,
        NULL
    );

    if (hwnd == NULL) {
        MessageBox(NULL, L"Не удалось создать окно.", L"Ошибка", MB_ICONERROR);
        GdiplusShutdown(gdiplusToken);
        return 0;
    }

    // Загрузка фонового изображения из URL
    if (!LoadImageFromURL(L"https://i.pinimg.com/originals/56/cb/5f/56cb5ff3d83e4159c447b04d5d3a333e.jpg", backgroundImage)) {
        MessageBox(hwnd, L"Не удалось загрузить фон. Приложение будет закрыто.", L"Ошибка", MB_ICONERROR);
        DestroyWindow(hwnd);
        GdiplusShutdown(gdiplusToken);
        return 0;
    }

    // Инициализация дополнительных изображений
    if (!InitializeImages()) {
        MessageBox(hwnd, L"Не удалось загрузить дополнительные изображения. Приложение будет закрыто.", L"Ошибка", MB_ICONERROR);
        DestroyWindow(hwnd);
        GdiplusShutdown(gdiplusToken);
        return 0;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    // Цикл сообщений
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Завершение работы с GDI+
    GdiplusShutdown(gdiplusToken);
    return 0;
}
