import socket
import struct
import time
import io
import ctypes
import zlib
import threading
from ctypes import wintypes
import win32gui
import win32ui
import win32con
import win32api
from PIL import Image
import numpy as np

# ==========================================
#    1. Windows API 定义
# ==========================================
user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32  # 引入 GDI32
ole32 = ctypes.windll.ole32

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    ctypes.windll.user32.SetProcessDPIAware()

# --- 关键类型定义 ---
# 强制定义句柄为 64位指针 (c_void_p)，防止 Python 当作 int(32位) 处理
HICON = ctypes.c_void_p
HBITMAP = ctypes.c_void_p
HGDIOBJ = ctypes.c_void_p
HDC = ctypes.c_void_p


# --- 结构体定义 ---
class ICONINFO(ctypes.Structure):
    _fields_ = [("fIcon", wintypes.BOOL),
                ("xHotspot", wintypes.DWORD),
                ("yHotspot", wintypes.DWORD),
                ("hbmMask", HBITMAP),  # 使用 c_void_p
                ("hbmColor", HBITMAP)]  # 使用 c_void_p


class BITMAP(ctypes.Structure):
    _fields_ = [('bmType', wintypes.LONG),
                ('bmWidth', wintypes.LONG),
                ('bmHeight', wintypes.LONG),
                ('bmWidthBytes', wintypes.LONG),
                ('bmPlanes', wintypes.WORD),
                ('bmBitsPixel', wintypes.WORD),
                ('bmBits', ctypes.c_void_p)]


# --- 函数参数类型定义 ---

# 1. GetIconInfo (User32)
user32.GetIconInfo.argtypes = [HICON, ctypes.POINTER(ICONINFO)]
user32.GetIconInfo.restype = wintypes.BOOL

# 2. DrawIconEx (User32)
user32.DrawIconEx.argtypes = [
    HDC,  # hdc
    wintypes.INT,  # xLeft
    wintypes.INT,  # yTop
    HICON,  # hIcon
    wintypes.INT,  # cxWidth
    wintypes.INT,  # cyWidth
    wintypes.UINT,  # istepIfAniCur
    HBITMAP,  # hbrFlickerFreeDraw
    wintypes.UINT  # diFlags
]
user32.DrawIconEx.restype = wintypes.BOOL

# 3. GetObjectW (GDI32)
gdi32.GetObjectW.argtypes = [HGDIOBJ, wintypes.INT, ctypes.c_void_p]
gdi32.GetObjectW.restype = wintypes.INT

# 4. DeleteObject (GDI32)
gdi32.DeleteObject.argtypes = [HGDIOBJ]
gdi32.DeleteObject.restype = wintypes.BOOL

# --- 钩子相关 ---
HWINEVENTHOOK = ctypes.c_void_p
WINEVENTPROC = ctypes.WINFUNCTYPE(
    None,
    HWINEVENTHOOK,
    wintypes.DWORD,
    wintypes.HWND,
    wintypes.LONG,
    wintypes.LONG,
    wintypes.DWORD,
    wintypes.DWORD
)

EVENT_OBJECT_NAMECHANGE = 0x800C
WINEVENT_OUTOFCONTEXT = 0x0000
OBJID_CURSOR = -9

# ==========================================
#           2. 全局变量与网络设置
# ==========================================
LISTEN_PORT = 5005
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", LISTEN_PORT))
sock.setblocking(False)

# ==========================================
# 禁止 Windows 因客户端断开而抛出 10054 错误
# ==========================================
try:
    # SIO_UDP_CONNRESET = 0x9800000C
    # 告诉内核：即使对方端口不可达，也不要抛出异常，当作无事发生
    sock.ioctl(socket.SIO_UDP_CONNRESET, False)
except Exception:
    pass

current_client_addr = None
last_processed_handle = 0
sent_hashes = set()
net_lock = threading.Lock()
_hook_ref = None


# ==========================================
#           3. 图像处理核心
# ==========================================

def get_real_cursor_size(hbmColor, hbmMask):
    """获取光标真实尺寸"""
    bmp = BITMAP()
    # 使用定义好 argtypes 的 gdi32.GetObjectW，而不是 ctypes.windll.gdi32...
    if hbmColor:
        if gdi32.GetObjectW(hbmColor, ctypes.sizeof(bmp), ctypes.byref(bmp)):
            return bmp.bmWidth, bmp.bmHeight
    if hbmMask:
        if gdi32.GetObjectW(hbmMask, ctypes.sizeof(bmp), ctypes.byref(bmp)):
            w = bmp.bmWidth
            h = bmp.bmHeight
            if not hbmColor: h = h // 2
            return w, h
    return win32api.GetSystemMetrics(win32con.SM_CXCURSOR), win32api.GetSystemMetrics(win32con.SM_CYCURSOR)


def capture_cursor_image_logic():
    try:
        info = win32gui.GetCursorInfo()
        hcursor_int = info[1]

        if hcursor_int == 0:
            return None

            # 转换为 c_void_p
        hcursor = HICON(hcursor_int)

        icon_info = ICONINFO()
        if not user32.GetIconInfo(hcursor, ctypes.byref(icon_info)):
            return None

        hot_x = icon_info.xHotspot
        hot_y = icon_info.yHotspot
        hbmMask = icon_info.hbmMask
        hbmColor = icon_info.hbmColor

        w, h = get_real_cursor_size(hbmColor, hbmMask)

        hdc_screen = win32gui.GetDC(0)
        hdc = win32ui.CreateDCFromHandle(hdc_screen)

        # 绘制黑色背景
        mem_dc_b = hdc.CreateCompatibleDC()
        bmp_b = win32ui.CreateBitmap()
        bmp_b.CreateCompatibleBitmap(hdc, w, h)
        mem_dc_b.SelectObject(bmp_b)
        mem_dc_b.FillSolidRect((0, 0, w, h), 0x000000)

        # 使用 DrawIconEx (已修正类型)
        user32.DrawIconEx(mem_dc_b.GetSafeHdc(), 0, 0, hcursor, w, h, 0, 0, 0x0003)

        bits_b = bmp_b.GetBitmapBits(True)
        img_b = Image.frombuffer('RGB', (w, h), bits_b, 'raw', 'BGRX', 0, 1)

        # 绘制白色背景
        mem_dc_w = hdc.CreateCompatibleDC()
        bmp_w = win32ui.CreateBitmap()
        bmp_w.CreateCompatibleBitmap(hdc, w, h)
        mem_dc_w.SelectObject(bmp_w)
        mem_dc_w.FillSolidRect((0, 0, w, h), 0xFFFFFF)

        user32.DrawIconEx(mem_dc_w.GetSafeHdc(), 0, 0, hcursor, w, h, 0, 0, 0x0003)

        bits_w = bmp_w.GetBitmapBits(True)
        img_w = Image.frombuffer('RGB', (w, h), bits_w, 'raw', 'BGRX', 0, 1)

        # 算法处理
        arr_b = np.array(img_b).astype(np.int16)
        arr_w = np.array(img_w).astype(np.int16)

        real_diff = arr_w - arr_b
        alpha_channel = 255 - np.max(real_diff, axis=2)
        alpha_channel = np.clip(alpha_channel, 0, 255).astype(np.uint8)

        lum_b = np.mean(arr_b, axis=2)
        lum_w = np.mean(arr_w, axis=2)
        is_xor = (lum_b > lum_w + 50)

        final_rgb = arr_b.copy()

        if np.any(is_xor):
            final_rgb[is_xor] = [255, 255, 255]
            alpha_channel[is_xor] = 255
            xor_mask = is_xor.astype(np.uint8)
            dilated = np.zeros_like(xor_mask)
            dilated[1:, :] |= xor_mask[:-1, :]
            dilated[:-1, :] |= xor_mask[1:, :]
            dilated[:, 1:] |= xor_mask[:, :-1]
            dilated[:, :-1] |= xor_mask[:, 1:]
            shadow_mask = (dilated == 1) & (is_xor == False)
            final_rgb[shadow_mask] = [0, 0, 0]
            alpha_channel[shadow_mask] = 255

        final_rgba = np.dstack((final_rgb, alpha_channel)).astype(np.uint8)
        img_final = Image.fromarray(final_rgba)

        # 资源清理
        mem_dc_b.DeleteDC()
        mem_dc_w.DeleteDC()
        win32gui.DeleteObject(bmp_b.GetHandle())
        win32gui.DeleteObject(bmp_w.GetHandle())
        win32gui.ReleaseDC(0, hdc_screen)

        # 使用 DeleteObject (已修正类型)
        if hbmMask: gdi32.DeleteObject(hbmMask)
        if hbmColor: gdi32.DeleteObject(hbmColor)

        output_buffer = io.BytesIO()
        img_final.save(output_buffer, format='PNG')
        return output_buffer.getvalue(), hot_x, hot_y, hcursor_int

    except Exception as e:
        import traceback
        traceback.print_exc()
        return None


# ==========================================
#           4. 任务处理 (子线程)
# ==========================================

def worker_process_cursor(trigger_hcursor):
    global current_client_addr, sent_hashes

    if not current_client_addr:
        return

    result = capture_cursor_image_logic()
    if not result:
        return

    png_data, hot_x, hot_y, real_hcursor = result

    img_hash = zlib.crc32(png_data) & 0xffffffff

    try:
        with net_lock:
            is_cached = img_hash in sent_hashes
            if not is_cached:
                sent_hashes.add(img_hash)

        if is_cached:
            packet = struct.pack('<BQii', 1, img_hash, hot_x, hot_y)
        else:
            header = struct.pack('<BQii', 0, img_hash, hot_x, hot_y)
            packet = header + png_data
            print(f"[发送] 新图片: {img_hash} 大小: {len(png_data)} bytes")

        sock.sendto(packet, current_client_addr)

    except Exception as e:
        print(f"Send Error: {e}")


# ==========================================
#           5. 钩子回调 (主线程)
# ==========================================

def on_cursor_event_callback(hWinEventHook, event, hwnd, idObject, idChild, dwEventThread, dwmsEventTime):
    global last_processed_handle
    if idObject == OBJID_CURSOR:
        try:
            info = win32gui.GetCursorInfo()
            current_hcursor = info[1]
            if current_hcursor != last_processed_handle:
                last_processed_handle = current_hcursor
                t = threading.Thread(target=worker_process_cursor, args=(current_hcursor,))
                t.daemon = True
                t.start()
        except Exception:
            pass
        except KeyboardInterrupt:
            # 正常退出信号，不打印异常信息
            pass


# ==========================================
#           6. 网络监听
# ==========================================

def listen_for_client():
    global current_client_addr, last_processed_handle, sent_hashes

    # 记录最后一次发送数据的时间
    last_keepalive_time = time.time()

    print(f"[网络] 监听端口 {LISTEN_PORT} 等待握手...")
    while True:
        try:
            # 1. 接收握手包
            try:
                data, addr = sock.recvfrom(1024)
                if data.decode('utf-8', errors='ignore').strip() == "CURSOR_HELLO":
                    if current_client_addr != addr:
                        print(f"[网络] 手机已连接: {addr}")
                        with net_lock:
                            current_client_addr = addr
                            last_processed_handle = 0
                            sent_hashes.clear()
                        # 新连接立即刷新
                        threading.Thread(target=worker_process_cursor, args=(0,)).start()
                        last_keepalive_time = time.time()
            except BlockingIOError:
                pass

            # 2. 心跳保活逻辑
            # 如果当前有连接，且距离上次发送已经过了 1 秒
            if current_client_addr and (time.time() - last_keepalive_time > 1.0):
                # 更新时间
                last_keepalive_time = time.time()

                # 强制触发一次 worker。
                # 因为 worker 内部有缓存判断 (sent_hashes)，
                # 所以如果光标没变，它只会发一个极其微小的“Type 1”数据包(十几字节)，不耗流量也不耗CPU。
                if last_processed_handle != 0:
                    t = threading.Thread(target=worker_process_cursor, args=(last_processed_handle,))
                    t.daemon = True
                    t.start()

        except Exception as e:
            print(e)

        # 循环间隔
        time.sleep(0.5)


# ==========================================
#           7. 程序入口
# ==========================================

if __name__ == "__main__":
    net_thread = threading.Thread(target=listen_for_client, daemon=True)
    net_thread.start()

    print("\n[系统] 初始化完成")

    WinEventProcType = WINEVENTPROC
    _hook_ref = WinEventProcType(on_cursor_event_callback)

    hook_id = user32.SetWinEventHook(
        EVENT_OBJECT_NAMECHANGE,
        EVENT_OBJECT_NAMECHANGE,
        0,
        _hook_ref,
        0,
        0,
        WINEVENT_OUTOFCONTEXT
    )

    if not hook_id:
        print("错误: 无法安装系统钩子")
        exit(1)

    try:
        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), 0, 0, 0) != 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
    except KeyboardInterrupt:
        print("\n程序已被用户终止")
    finally:
        try:
            user32.UnhookWinEvent(hook_id)
        except:
            pass