#pragma once
#include <windows.h>
#include <gdiplus.h>
#include <vector>
#include <cstdint>
#include <memory>
#include "logger.hpp"

#pragma comment(lib, "gdiplus.lib")

using namespace Gdiplus;

class CursorCapture {
private:
    HDC hdc_screen = nullptr;
    HDC hdc_mem_black = nullptr;
    HDC hdc_mem_white = nullptr;
    HBITMAP hbmp_black = nullptr;
    HBITMAP hbmp_white = nullptr;
    HBITMAP hbmask = nullptr;
    HBITMAP hbmcolor = nullptr;
    
public:
    CursorCapture() = default;
    ~CursorCapture() { Cleanup(); }
    
    void Cleanup() {
        if (hdc_mem_black) { DeleteDC(hdc_mem_black); hdc_mem_black = nullptr; }
        if (hdc_mem_white) { DeleteDC(hdc_mem_white); hdc_mem_white = nullptr; }
        if (hbmp_black) { DeleteObject(hbmp_black); hbmp_black = nullptr; }
        if (hbmp_white) { DeleteObject(hbmp_white); hbmp_white = nullptr; }
        if (hdc_screen) { ReleaseDC(nullptr, hdc_screen); hdc_screen = nullptr; }
        if (hbmask) { DeleteObject(hbmask); hbmask = nullptr; }
        if (hbmcolor) { DeleteObject(hbmcolor); hbmcolor = nullptr; }
    }
    
    bool Capture(std::vector<BYTE>& out_png_data, int& out_hotspot_x, int& out_hotspot_y, DWORD& out_hcursor) {
        try {
            CURSORINFO ci = {sizeof(CURSORINFO)};
            if (!GetCursorInfo(&ci) || ci.flags != CURSOR_SHOWING || ! ci.hCursor) {
                return false;
            }
            
            ICONINFO ii = {};
            if (!GetIconInfo(ci.hCursor, &ii)) {
                return false;
            }
            
            out_hotspot_x = ii. xHotspot;
            out_hotspot_y = ii. yHotspot;
            hbmask = ii.hbmMask;
            hbmcolor = ii.hbmColor;
            
            // 获取位图大小
            BITMAP bm = {};
            GetObject(hbmcolor ?  hbmcolor : hbmask, sizeof(BITMAP), &bm);
            int w = bm.bmWidth;
            int h = hbmcolor ? bm.bmHeight : (bm.bmHeight / 2);
            
            if (w > 512 || h > 512) {
                w = min(w, 512);
                h = min(h, 512);
            }
            
            hdc_screen = GetDC(nullptr);
            hdc_mem_black = CreateCompatibleDC(hdc_screen);
            hdc_mem_white = CreateCompatibleDC(hdc_screen);
            
            hbmp_black = CreateCompatibleBitmap(hdc_screen, w, h);
            hbmp_white = CreateCompatibleBitmap(hdc_screen, w, h);
            
            SelectObject(hdc_mem_black, hbmp_black);
            SelectObject(hdc_mem_white, hbmp_white);
            
            // 黑色背景
            HBRUSH hbrush_black = CreateSolidBrush(RGB(0, 0, 0));
            RECT rect = {0, 0, w, h};
            FillRect(hdc_mem_black, &rect, hbrush_black);
            DrawIconEx(hdc_mem_black, 0, 0, ci.hCursor, w, h, 0, nullptr, DI_NORMAL);
            DeleteObject(hbrush_black);
            
            // 白色背景
            HBRUSH hbrush_white = CreateSolidBrush(RGB(255, 255, 255));
            FillRect(hdc_mem_white, &rect, hbrush_white);
            DrawIconEx(hdc_mem_white, 0, 0, ci. hCursor, w, h, 0, nullptr, DI_NORMAL);
            DeleteObject(hbrush_white);
            
            // 获取像素数据（使用GDI+保存为PNG）
            Bitmap* bmp_result = CreateBitmapFromCursor(hdc_mem_black, hdc_mem_white, w, h);
            if (! bmp_result) return false;
            
            // 保存为PNG到内存
            if (!SaveBitmapToPNG(bmp_result, out_png_data)) {
                delete bmp_result;
                return false;
            }
            
            delete bmp_result;
            out_hcursor = (DWORD)ci.hCursor;
            return true;
            
        } catch (const std::exception& e) {
            g_logger.Error(std::string("Capture error: ") + e.what());
            return false;
        }
    }
    
private:
    Bitmap* CreateBitmapFromCursor(HDC hdc_black, HDC hdc_white, int w, int h) {
        // 获取黑白背景下的像素数据，计算透明度
        // 这里简化为直接创建ARGB位图
        Bitmap* bmp = new Bitmap(w, h, PixelFormat32bppARGB);
        
        // 从hdc_black获取数据
        BITMAPINFOHEADER bih = {};
        bih.biSize = sizeof(BITMAPINFOHEADER);
        bih. biWidth = w;
        bih.biHeight = -h;
        bih.biPlanes = 1;
        bih.biBitCount = 32;
        bih.biCompression = BI_RGB;
        
        std::vector<DWORD> pixels_black(w * h);
        std::vector<DWORD> pixels_white(w * h);
        
        GetDIBits(hdc_black, (HBITMAP)GetCurrentObject(hdc_black, OBJ_BITMAP),
                  0, h, pixels_black.data(), (BITMAPINFO*)&bih, DIB_RGB_COLORS);
        GetDIBits(hdc_white, (HBITMAP)GetCurrentObject(hdc_white, OBJ_BITMAP),
                  0, h, pixels_white.data(), (BITMAPINFO*)&bih, DIB_RGB_COLORS);
        
        // 遍历像素，计算alpha
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                int idx = y * w + x;
                DWORD pb = pixels_black[idx];
                DWORD pw = pixels_white[idx];
                
                BYTE rb = GetRValue(pb), gb = GetGValue(pb), bb = GetBValue(pb);
                BYTE rw = GetRValue(pw), gw = GetGValue(pw), bw = GetBValue(pw);
                
                // 计算alpha (Python: alpha_channel = 255 - np.max(real_diff, axis=2))
                int diff_r = rw - rb, diff_g = gw - gb, diff_b = bw - bb;
                int max_diff = max({abs(diff_r), abs(diff_g), abs(diff_b)});
                BYTE alpha = 255 - (BYTE)min(255, max_diff);
                
                DWORD color = ARGB(alpha, rb, gb, bb);
                bmp->SetPixel(x, y, Color(color));
            }
        }
        
        return bmp;
    }
    
    bool SaveBitmapToPNG(Bitmap* bmp, std::vector<BYTE>& out_data) {
        CLSID pngClsid;
        GetEncoderClsid(L"image/png", &pngClsid);
        
        IStream* pStream = nullptr;
        CreateStreamOnHGlobal(nullptr, TRUE, &pStream);
        
        if (bmp->Save(pStream, &pngClsid, nullptr) != Ok) {
            pStream->Release();
            return false;
        }
        
        HGLOBAL hGlobal = nullptr;
        GetHGlobalFromStream(pStream, &hGlobal);
        
        BYTE* pData = (BYTE*)GlobalLock(hGlobal);
        SIZE_T size = GlobalSize(hGlobal);
        
        out_data.assign(pData, pData + size);
        
        GlobalUnlock(hGlobal);
        pStream->Release();
        
        return true;
    }
    
    static bool GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
        UINT num = 0, size = 0;
        ImageCodecInfo* pImageCodecInfo = nullptr;
        GetImageEncodersSize(&num, &size);
        if (size == 0) return false;
        
        pImageCodecInfo = (ImageCodecInfo*)malloc(size);
        GetImageEncoders(num, size, pImageCodecInfo);
        
        for (UINT i = 0; i < num; i++) {
            if (wcscmp(pImageCodecInfo[i].MimeType, format) == 0) {
                *pClsid = pImageCodecInfo[i].Clsid;
                free(pImageCodecInfo);
                return true;
            }
        }
        free(pImageCodecInfo);
        return false;
    }
};