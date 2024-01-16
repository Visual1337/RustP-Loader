#pragma once

namespace Tools
{
    wstring generateRandomString(size_t length)
    {
        static wstring charset = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        wstring result;
        result.resize(length);

        srand(time(NULL));
        for (int i = 0; i < length; i++)
            result[i] = charset[rand() % charset.length()];

        return result;
    }
    void GetFilesInDirectory(const char* directory)
    {
        WIN32_FIND_DATA FindFileData;
        HANDLE hf;
        hf = FindFirstFile(directory, &FindFileData);
        if (hf != INVALID_HANDLE_VALUE) {
            do {
                std::cout << FindFileData.cFileName << "\n";
            } while (FindNextFile(hf, &FindFileData) != 0);
            FindClose(hf);
        }
    }
}