import socket, threading, json, struct, os, sys
import tkinter as tk
from tkinter import scrolledtext, messagebox
from PIL import Image, ImageTk
from io import BytesIO
import tempfile
import subprocess

HOST = "127.0.0.1"
PORT = 5000

def open_with_os(path):
    if sys.platform.startswith("win"):
        os.startfile(path)
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])

class ServerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Server (Sunucu)")
        root.geometry("760x580")

        top = tk.Frame(root); top.pack(fill="x", padx=8, pady=6)
        self.status = tk.Label(top, text=f"Durum: Beklemede {HOST}:{PORT}")
        self.status.pack(side="left")

        mid = tk.Frame(root); mid.pack(fill="both", expand=True, padx=8, pady=6)
        self.log = scrolledtext.ScrolledText(mid, height=14, state="disabled")
        self.log.pack(fill="both", expand=True)

        self.image_label = tk.Label(root)
        self.image_label.pack(pady=8)

        bottom = tk.Frame(root); bottom.pack(fill="x", padx=8, pady=6)
        tk.Label(bottom, text="İstemciye mesaj:").pack(anchor="w")
        self.entry = tk.Entry(bottom)
        self.entry.pack(side="left", fill="x", expand=True)
        tk.Button(bottom, text="Gönder", command=self.send_text).pack(side="left", padx=6)

        self.sock = None
        self.conn = None
        self.addr = None
        threading.Thread(target=self.start_server, daemon=True).start()

    def log_write(self, s):
        self.log.configure(state="normal")
        self.log.insert("end", s + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def start_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((HOST, PORT))
            self.sock.listen(1)
            self.update_status(f"Dinlemede: {HOST}:{PORT} (istemci bekleniyor)")
            self.conn, self.addr = self.sock.accept()
            self.update_status(f"Bağlandı: {self.addr}")
            self.log_write(f"[+] İstemci bağlandı: {self.addr}")
            threading.Thread(target=self.handle_client, daemon=True).start()
        except Exception as e:
            self.update_status(f"Hata: {e}")
            messagebox.showerror("Sunucu Hatası", str(e))

    def update_status(self, s):
        def _():
            self.status.config(text=f"Durum: {s}")
        self.root.after(0, _)

    def handle_client(self):
        try:
            while True:
                header_len_raw = self.recvall(4)
                if not header_len_raw:
                    self.log_write("[-] Bağlantı kapandı.")
                    break
                header_len = struct.unpack(">I", header_len_raw)[0]
                header_json = self.recvall(header_len).decode("utf-8")
                header = json.loads(header_json)
                typ = header.get("type")

                if typ == "text":
                    size = header.get("size", 0)
                    data = self.recvall(size).decode("utf-8") if size else ""
                    cipher = header.get("cipher", "-")
                    mode = header.get("mode", "-")
                    self.log_write(f"[İSTEMCİ] ({cipher}/{mode}) {data}")

                elif typ == "file":
                    size = header["size"]
                    filename = header.get("filename", "dosya")
                    mimetype = header.get("mimetype", "application/octet-stream")
                    data = self.recvall(size)

                    if mimetype.startswith("image/"):
                        img = Image.open(BytesIO(data))
                        img.thumbnail((640, 360))
                        tk_img = ImageTk.PhotoImage(img)
                        def _show():
                            self.image_label.configure(image=tk_img)
                            self.image_label.image = tk_img
                        self.root.after(0, _show)
                        self.log_write(f"[DOSYA] Resim alındı: {filename} ({len(data)} bayt)")
                    else:
                        ext = os.path.splitext(filename)[1] or ""
                        tmpdir = tempfile.gettempdir()
                        save_path = os.path.join(tmpdir, f"server_recv{ext}")
                        with open(save_path, "wb") as f:
                            f.write(data)
                        self.log_write(f"[DOSYA] Kaydedildi: {save_path} ({mimetype})")
                        open_with_os(save_path)
                else:
                    self.log_write(f"[!] Bilinmeyen tür: {typ}")

        except Exception as e:
            self.log_write(f"[HATA] {e}")
        finally:
            if self.conn:
                try: self.conn.close()
                except: pass

    def recvall(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def send_text(self):
        if not self.conn:
            messagebox.showwarning("Uyarı", "İstemci bağlı değil.")
            return
        msg = self.entry.get().strip()
        if not msg:
            return
        body = msg.encode("utf-8")
        header = json.dumps({"type": "text", "size": len(body), "cipher": "server_plain", "mode": "-"}).encode("utf-8")
        packet = struct.pack(">I", len(header)) + header + body
        try:
            self.conn.sendall(packet)
            self.log_write(f"[SUNUCU] {msg}")
            self.entry.delete(0, "end")
        except Exception as e:
            messagebox.showerror("Gönderme Hatası", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerGUI(root)
    root.mainloop()
