#!/usr/bin/env python3
# ultimate_esp_inspector_v1.0.py
# Comprehensive, database-driven GUI Hardware Inspector for all Espressif chips.
# v1.0: The "Analyst" Edition.
# - Fixed Bluetooth MAC display logic for absolute correctness.
# - Enhanced authenticity analysis to show the OUI code for verification.
# - Added raw "Features" string from esptool for expert-level detail.
# - Final code review for integrity, balance, and focus.

import sys
import threading
import re
import traceback
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import time
import multiprocessing
import io
from contextlib import redirect_stdout

# --- DỄ DÀNG TÙY CHỈNH ---
REPORT_FONT_SIZE = 10
DEFAULT_WINDOW_WIDTH = 920
DEFAULT_WINDOW_HEIGHT = 720
# -------------------------

try:
    from serial.tools import list_ports
    import esptool
except ImportError:
    print("FATAL ERROR: Required packages 'pyserial' or 'esptool' not found.")
    sys.exit(1)

COMMON_BAUDS = ["115200", "230400", "460800", "921600"]
# --- CSDL CHIP TOÀN DIỆN NHẤT ---
FLASH_MANUFACTURERS = { "0x20": "XMC", "0x68": "XMC", "0xC8": "GigaDevice", "0xEF": "Winbond", "0x1C": "EON", "0x0B": "Puya", "0xA1": "Fudan", "0xC2": "Macronix (MX)", "0xE0": "Fremont"}
CHIP_DATABASE = {
    "ESP32": { "name": "ESP32", "architecture": "Xtensa® dual-core 32-bit LX6", "cores": 2, "cpu_freq_mhz": [160, 240], "sram_kb": 520, "rom_kb": 448, "wifi": "Wi-Fi 4 (802.11 b/g/n)", "bluetooth": "Bluetooth v4.2 BR/EDR + BLE", "features": ["ADC", "DAC", "TWAI® (CAN)", "Cảm biến Hall"] },
    "ESP32-D2WD": { "name": "ESP32-D2WD", "architecture": "Xtensa® dual-core 32-bit LX6", "cores": 2, "cpu_freq_mhz": [160, 240], "sram_kb": 520, "rom_kb": 448, "wifi": "Wi-Fi 4 (802.11 b/g/n)", "bluetooth": "Bluetooth v4.2 BR/EDR + BLE", "features": ["Flash 2MB tích hợp", "ADC", "DAC"] },
    "ESP32-S2": { "name": "ESP32-S2", "architecture": "Xtensa® single-core 32-bit LX7", "cores": 1, "cpu_freq_mhz": [160, 240], "sram_kb": 320, "rom_kb": 128, "wifi": "Wi-Fi 4 (802.11 b/g/n)", "bluetooth": None, "features": ["USB OTG", "LCD/Camera Interface", "Cảm biến nhiệt độ"] },
    "ESP32-S3": { "name": "ESP32-S3", "architecture": "Xtensa® dual-core 32-bit LX7", "cores": 2, "cpu_freq_mhz": [160, 240], "sram_kb": 512, "rom_kb": 384, "wifi": "Wi-Fi 4 (802.11 b/g/n)", "bluetooth": "Bluetooth 5 (LE)", "features": ["AI Acceleration", "USB OTG", "LCD/Camera Interface"] },
    "ESP32-C2": { "name": "ESP32-C2 (ESP8685)", "architecture": "RISC-V 32-bit single-core", "cores": 1, "cpu_freq_mhz": [120], "sram_kb": 272, "rom_kb": 576, "wifi": "Wi-Fi 4 (802.11 b/g/n)", "bluetooth": "Bluetooth 5 (LE)", "features": ["Low Power Consumption"] },
    "ESP32-C3": { "name": "ESP32-C3", "architecture": "RISC-V 32-bit single-core", "cores": 1, "cpu_freq_mhz": [160], "sram_kb": 400, "rom_kb": 384, "wifi": "Wi-Fi 4 (802.11 b/g/n)", "bluetooth": "Bluetooth 5 (LE)", "features": ["ADC", "TWAI® (CAN)", "Cảm biến nhiệt độ"] },
    "ESP32-C5": { "name": "ESP32-C5", "architecture": "RISC-V 32-bit single-core", "cores": 1, "cpu_freq_mhz": [240], "sram_kb": 400, "rom_kb": 384, "wifi": "Wi-Fi 6 (802.11ax) Dual Band", "bluetooth": "Bluetooth 5 (LE)", "features": ["Dual Band 2.4/5GHz Wi-Fi"] },
    "ESP32-C6": { "name": "ESP32-C6", "architecture": "RISC-V 32-bit single-core", "cores": 1, "cpu_freq_mhz": [160], "sram_kb": 512, "rom_kb": 320, "wifi": "Wi-Fi 6 (802.11ax)", "bluetooth": "Bluetooth 5.3 (LE)", "features": ["802.15.4 (Thread/Zigbee)", "Low-power LP Core"] },
    "ESP32-C61": { "name": "ESP32-C61", "architecture": "RISC-V 32-bit single-core", "cores": 1, "cpu_freq_mhz": [160], "sram_kb": 272, "rom_kb": 0, "wifi": "Wi-Fi 6 (802.11ax)", "bluetooth": "Bluetooth 5.3 (LE)", "features": ["Cost-Effective Wi-Fi 6"] },
    "ESP32-H2": { "name": "ESP32-H2", "architecture": "RISC-V 32-bit single-core", "cores": 1, "cpu_freq_mhz": [96], "sram_kb": 320, "rom_kb": 128, "wifi": None, "bluetooth": "Bluetooth 5.3 (LE)", "features": ["802.15.4 (Thread/Zigbee)", "Low Power Consumption"] },
    "ESP32-P4": { "name": "ESP32-P4", "architecture": "RISC-V dual-core 32-bit", "cores": 2, "cpu_freq_mhz": [400], "sram_kb": 768, "rom_kb": 0, "wifi": None, "bluetooth": None, "features": ["High Performance", "MIPI-DSI/CSI", "H.264 Encoder", "2D Graphics Acceleration"] },
    "ESP8266": { "name": "ESP8266EX", "architecture": "Xtensa® single-core 32-bit L106", "cores": 1, "cpu_freq_mhz": [80, 160], "sram_kb": 96, "rom_kb": 64, "wifi": "Wi-Fi 4 (802.11 b/g/n)", "bluetooth": None, "features": ["ADC"] },
    "ESP8285": { "name": "ESP8285", "architecture": "Xtensa® single-core 32-bit L106", "cores": 1, "cpu_freq_mhz": [80, 160], "sram_kb": 96, "rom_kb": 64, "wifi": "Wi-Fi 4 (802.11 b/g/n)", "bluetooth": None, "features": ["Flash 1MB tích hợp", "ADC"] }
}
ESPRESSIF_OUIS = [ "CC:50:E3", "80:B5:4E", "8C:D0:B2", "94:A9:90", "E0:8C", "80:B5:E4", "7C:9E:BD", "A0:20:A6", "A4:7B:9D", "BC:DD:C2", "24:0A:C4", "24:B2:DE", "30:AE:A4", "60:01:94", "D8:A0:1D", "DC:4F:22" ]

# ---------------------- Core Logic ----------------------
def run_esptool_command(args):
    original_argv = sys.argv
    try:
        sys.argv = ['esptool.py'] + args; output_capture = io.StringIO()
        with redirect_stdout(output_capture): esptool.main()
        return output_capture.getvalue()
    except Exception as e: raise e
    finally: sys.argv = original_argv

def list_com_ports_local():
    try: return [p.device for p in list_ports.comports()]
    except Exception: return []

def parse_esptool_output(output_dict):
    full_output = "\n".join(output_dict.values()); info = {'raw': full_output}
    m = re.search(r"Detecting chip type...\s*([^\r\n]+)", full_output, re.IGNORECASE);
    if m: info['chip_name_key'] = m.group(1).strip()
    m = re.search(r"(?:Chip is|Chip type:)\s*([^\r\n]+)", full_output, re.IGNORECASE);
    if m: info['chip_line'] = m.group(1).strip()
    m = re.search(r"Features:\s*([^\r\n]+)", full_output, re.IGNORECASE);
    if m: info['features_line'] = m.group(1).strip()
    m = re.search(r"(?:Crystal is|Crystal frequency:)\s*([^\r\n]+)", full_output, re.IGNORECASE);
    if m: info['crystal'] = m.group(1).strip()
    if info.get('chip_line'):
        m = re.search(r"revision\s*v?([0-9.]+)", info['chip_line'], re.IGNORECASE);
        if m: info['revision'] = m.group(1)
    m = re.search(r"MAC\s*[:=]\s*([0-9A-Fa-f:.]{12,17})", full_output);
    if m: info['mac'] = "".join(re.findall("[0-9A-Fa-f]", m.group(1).upper()))
    m = re.search(r"Manufacturer:\s*([0-9a-fA-F_xX]+)", full_output);
    if m: info["flash_manufacturer"] = m.group(1)
    m = re.search(r"Device:\s*([0-9a-fA-F_xX]+)", full_output);
    if m: info["flash_device"] = m.group(1)
    m = re.search(r"Detected flash size:\s*([0-9.]+)MB", full_output, re.IGNORECASE);
    if m: info['flash_mb'] = float(m.group(1))
    m = re.search(r"Status value:\s*([^\r\n]+)", full_output, re.IGNORECASE);
    if m: info['status_value'] = m.group(1).strip()
    m = re.search(r"(?:PSRAM|Embedded PSRAM)\s+(\d+)MB", info.get('features_line', ''), re.IGNORECASE);
    if m: info['psram_mb'] = int(m.group(1))
    return info

def derive_mac_addresses(base_mac_hex):
    if not base_mac_hex or len(base_mac_hex) != 12: return {}
    try:
        b = bytes.fromhex(base_mac_hex)
        def fmt(offset):
            n = (int.from_bytes(b, 'big') + offset).to_bytes(6, 'big')
            return ":".join(f"{x:02X}" for x in n)
        return {"MAC Wi-Fi Station": fmt(0), "MAC Wi-Fi AP": fmt(1), "MAC Bluetooth": fmt(2)}
    except Exception: return {}

def get_chip_data(chip_name_key):
    if not chip_name_key: return None
    sorted_keys = sorted(CHIP_DATABASE.keys(), key=len, reverse=True)
    if chip_name_key in sorted_keys: return CHIP_DATABASE[chip_name_key]
    for key in sorted_keys:
        if key in chip_name_key: return CHIP_DATABASE[key]
    return None

# ---------------------- GUI ----------------------
class InspectorApp:
    def __init__(self, root):
        self.root = root; self.root.title("ESP Hardware Inspector v1.0")
        self.root.geometry(f"{DEFAULT_WINDOW_WIDTH}x{DEFAULT_WINDOW_HEIGHT}")
        self.stop_scan = threading.Event(); self.is_detecting = threading.Event()
        self.create_widgets()
    def start_background_tasks(self):
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        threading.Thread(target=self._auto_scan_ports, daemon=True).start()
        self.set_status("Sẵn sàng")
    def create_widgets(self):
        frm = ttk.Frame(self.root, padding=10); frm.grid(sticky="nsew", row=0, column=0)
        self.root.columnconfigure(0, weight=1); self.root.rowconfigure(0, weight=1)
        controls_frame = ttk.LabelFrame(frm, text=" Cài đặt kết nối ", padding=(10, 5))
        controls_frame.grid(row=0, column=0, columnspan=3, sticky="ew", padx=5, pady=5)
        controls_frame.columnconfigure(1, weight=1)
        ttk.Label(controls_frame, text="COM Port:").grid(row=0, column=0, sticky="w", pady=2, padx=(0, 5))
        self.port_cb = ttk.Combobox(controls_frame, values=[], width=12, state="readonly"); self.port_cb.grid(row=0, column=1, sticky="ew")
        self.var_auto_scan = tk.BooleanVar(value=True)
        ttk.Checkbutton(controls_frame, text="Tự động quét", variable=self.var_auto_scan).grid(row=0, column=2, padx=5)
        ttk.Label(controls_frame, text="Baudrate:").grid(row=0, column=3, sticky="w", padx=(10, 5))
        self.baud_cb = ttk.Combobox(controls_frame, values=COMMON_BAUDS, width=10)
        self.baud_cb.grid(row=0, column=4, sticky="w"); self.baud_cb.set(COMMON_BAUDS[0])
        buttons_frame = ttk.LabelFrame(frm, text=" Tác vụ ", padding=(10, 5))
        buttons_frame.grid(row=1, column=0, columnspan=3, sticky="ew", padx=5, pady=5)
        self.detect_btn = ttk.Button(buttons_frame, text="KIỂM TRA TOÀN DIỆN", command=self.on_detect, style="Accent.TButton")
        self.detect_btn.pack(side="left", padx=(0,5))
        ttk.Button(buttons_frame, text="Lưu Báo Cáo", command=self.on_save).pack(side="left", padx=5)
        ttk.Button(buttons_frame, text="Xóa", command=self.on_clear).pack(side="left", padx=5)
        self.var_debug = tk.BooleanVar(value=False)
        ttk.Checkbutton(buttons_frame, text="Hiển thị Output Thô", variable=self.var_debug).pack(side="left", padx=(15,0))
        self.txt = tk.Text(frm, width=100, height=25, wrap="word", font=("Consolas", REPORT_FONT_SIZE), relief="sunken", borderwidth=1)
        self.txt.grid(row=2, column=0, columnspan=3, pady=(5,0), sticky="nsew")
        frm.rowconfigure(2, weight=1); frm.columnconfigure(0, weight=1)
        vsb = ttk.Scrollbar(frm, orient="vertical", command=self.txt.yview)
        vsb.grid(row=2, column=3, sticky="ns"); self.txt.configure(yscrollcommand=vsb.set)
        self.status = ttk.Label(frm, text="Sẵn sàng"); self.status.grid(row=3, column=0, columnspan=3, sticky="w", pady=(6,0))
        style = ttk.Style(); style.configure("Accent.TButton", font=('Segoe UI', 10, 'bold'), foreground="blue")
        self.txt.tag_configure('green', foreground='#009E73'); self.txt.tag_configure('blue', foreground='#0072B2'); self.txt.tag_configure('red', foreground='#D55E00')
        self.txt.tag_configure('header', font=("Consolas", REPORT_FONT_SIZE, 'bold'))

    def _auto_scan_ports(self):
        while not self.stop_scan.is_set():
            if self.var_auto_scan.get() and not self.is_detecting.is_set():
                try:
                    current_selection = self.port_cb.get(); new_ports = list_com_ports_local()
                    self.root.after(0, self.update_port_list, current_selection, new_ports)
                except Exception: traceback.print_exc()
            time.sleep(2)
    def update_port_list(self, current_selection, new_ports):
        if self.root.winfo_exists():
            if tuple(new_ports) != self.port_cb['values']:
                self.port_cb['values'] = new_ports
                if current_selection in new_ports: self.port_cb.set(current_selection)
                elif new_ports: self.port_cb.set(new_ports[0])
                else: self.port_cb.set("")
    def on_closing(self): self.stop_scan.set(); self.root.destroy()
    def log(self, s, tag=None): self.txt.insert("end", s + "\n", tag); self.txt.see("end")
    def on_clear(self, clear_status=True):
        self.txt.delete("1.0", "end");
        if clear_status: self.set_status("Sẵn sàng")
    def on_save(self):
        content = self.txt.get("1.0", "end").strip()
        if not content: messagebox.showinfo("Lưu", "Không có nội dung để lưu.")
        else:
            fpath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text File","*.txt")])
            if fpath:
                try:
                    with open(fpath, "w", encoding="utf-8") as f: f.write(content)
                    messagebox.showinfo("Lưu", f"Báo cáo đã được lưu vào {fpath}")
                except Exception as e: messagebox.showerror("Lỗi Lưu", str(e))
    def set_status(self, s): self.root.after(0, lambda: self.status.config(text=s))
    def on_detect(self):
        port = self.port_cb.get().strip()
        if not port: messagebox.showwarning("Thiếu Cổng", "Vui lòng chọn cổng COM.")
        else:
            self.on_clear(clear_status=False); self.set_status(f"Đang kiểm tra trên {port}...")
            self.detect_btn.config(state="disabled"); self.is_detecting.set()
            threading.Thread(target=self._detect_thread, args=(port, self.baud_cb.get()), daemon=True).start()
            
    def _display_formatted_report(self, info):
        self.on_clear(clear_status=False)
        if self.var_debug.get():
            self.log("--- OUTPUT THÔ TỪ ESPTOOL " + "-"*48, 'header')
            self.log(info.get('raw', 'Không có output thô.').strip()); self.log("-" * 72 + "\n")
        
        chip_data = get_chip_data(info.get('chip_name_key'))
        man_id = info.get('flash_manufacturer', 'N/A')
        man_name = FLASH_MANUFACTURERS.get(man_id.lower(), "Không rõ")
        base_mac_hex = info.get('mac')
        base_mac_formatted = ":".join(base_mac_hex[i:i+2] for i in range(0, 12, 2)) if base_mac_hex else None
        
        report_data = []
        report_data.append(("Thông tin Động (đọc từ chip)", None, 'header'))
        report_data.append(("  Tên chip đầy đủ", info.get('chip_line', 'N/A'), None))
        report_data.append(("  Các tính năng (Features)", info.get('features_line', 'N/A'), None)) # NEW
        report_data.append(("  Phiên bản Silicon", info.get('revision', 'N/A'), None))
        report_data.append(("  Tần số thạch anh", info.get('crystal', 'N/A'), None))
        
        report_data.append(("Thông tin Chip Flash & PSRAM", None, 'header'))
        report_data.append(("  Nhà sản xuất Flash", f"{man_name} ({man_id})", None))
        report_data.append(("  ID Flash", info.get('flash_device', 'N/A'), None))
        report_data.append(("  Kích thước Flash", f"{info.get('flash_mb', 0):.2f} MB" if 'flash_mb' in info else "N/A", None))
        if 'psram_mb' in info: report_data.append(("  Kích thước PSRAM", f"{info['psram_mb']} MB", None))
        else: report_data.append(("  Kích thước PSRAM", "Không hỗ trợ", None))
        
        report_data.append(("Thông số Kỹ thuật (tra cứu từ CSDL)", None, 'header'))
        if chip_data:
            report_data.append(("  Loại chip", chip_data['name'], None)); report_data.append(("  Kiến trúc CPU", chip_data['architecture'], None))
            report_data.append(("  Số nhân CPU", chip_data['cores'], None)); report_data.append(("  Tần số CPU hỗ trợ", f"{', '.join(map(str, chip_data['cpu_freq_mhz']))} MHz", None))
            report_data.append(("  Kích thước SRAM", f"{chip_data['sram_kb']} KB", None)); report_data.append(("  Kích thước ROM", f"{chip_data['rom_kb']} KB", None))
        else: report_data.append(("  Loại chip", f"{info.get('chip_name_key', 'Unknown')} (Không có trong CSDL)", 'red'))
        
        report_data.append(("Mạng & Kết nối", None, 'header'))
        report_data.append(("  Chuẩn Wi-Fi", (chip_data.get('wifi') if chip_data else None) or "Không hỗ trợ", None))
        report_data.append(("  Chuẩn Bluetooth", (chip_data.get('bluetooth') if chip_data else None) or "Không hỗ trợ", None))
        if base_mac_hex:
            macs = derive_mac_addresses(base_mac_hex)
            if chip_data and chip_data.get('wifi'):
                report_data.append(("    + MAC Wi-Fi Station", macs.get("MAC Wi-Fi Station"), None))
                report_data.append(("    + MAC Wi-Fi AP", macs.get("MAC Wi-Fi AP"), None))
            if chip_data and chip_data.get('bluetooth'):
                report_data.append(("    + MAC Bluetooth", macs.get("MAC Bluetooth"), None))
        else: report_data.append(("  Địa chỉ MAC", "Không đọc được", 'red'))
        
        if chip_data and chip_data.get('features'):
            report_data.append(("Tính năng Nổi bật", None, 'header')); report_data.append(("", ", ".join(chip_data['features']), None))

        report_data.append(("Phân tích Nguồn gốc", None, 'header'))
        if base_mac_formatted:
            oui = ":".join(base_mac_formatted.split(":")[:3])
            is_genuine_oui = any(base_mac_formatted.startswith(o) for o in ESPRESSIF_OUIS)
            if is_genuine_oui:
                report_data.append(("  Chip Xử Lý (SoC)", f"SoC Chính hãng (OUI: {oui} khớp với Espressif)", 'green'))
                if "espressif" in man_name.lower(): report_data.append(("  Board/Module", "Module chính thức từ Espressif (DevKit)", 'green'))
                else: report_data.append(("  Board/Module", f"Module của bên thứ ba (dùng Flash từ {man_name})", 'blue'))
            else:
                report_data.append(("  Chip Xử Lý (SoC)", f"Không xác định (OUI: {oui} không khớp, có nguy cơ là hàng clone)", 'red'))
        else: report_data.append(("  Chip Xử Lý (SoC)", "Không thể xác thực (thiếu MAC)", 'red'))

        key_width = max((len(k) for k, v, t in report_data if k and not k.startswith("---") and k.strip() != ""), default=25) + 2
        for key, value, tag in report_data:
            if value is None: self.log(f"\n{key}", tag)
            elif key == "": self.txt.insert("end", f"  {value}\n", tag)
            else:
                self.txt.insert("end", f"{key+':':<{key_width}} ")
                self.txt.insert("end", f"{value}\n", tag)
                
    def _detect_thread(self, port, baud):
        try:
            outputs = {}
            for name in ['chip_id', 'flash_id', 'read_mac']:
                self.set_status(f"Đang chạy {name}..."); args = ['--port', port, '--baud', baud, name]
                outputs[name] = run_esptool_command(args)
            info = parse_esptool_output(outputs)
            self.root.after(0, self._display_formatted_report, info)
        except Exception as e:
            error_str = str(e)
            if "PermissionError" in error_str or "could not open port" in error_str.lower():
                self.root.after(0, lambda: messagebox.showerror("Lỗi Truy Cập Cổng COM", f"Không thể mở cổng '{port}'.\n\nCổng này đang được sử dụng bởi một chương trình khác (Arduino IDE, PlatformIO, PuTTY,...).\n\nVui lòng đóng các chương trình đó và thử lại."))
                self.root.after(0, self.on_clear)
            else:
                self.root.after(0, self.on_clear, False)
                self.root.after(0, self.log, "ĐÃ XẢY RA LỖI KHÁC:\n" + error_str);
        finally:
            self.root.after(0, lambda: self.set_status("Lỗi trong quá trình kiểm tra." if 'e' in locals() else "Hoàn thành."))
            self.root.after(0, lambda: self.detect_btn.config(state="normal"))
            self.is_detecting.clear()

def main():
    root = tk.Tk(); app = InspectorApp(root)
    root.after(100, app.start_background_tasks); root.mainloop()

if __name__ == '__main__':
    multiprocessing.freeze_support(); main()