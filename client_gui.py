import socket, threading, json, struct, os, sys, mimetypes
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from PIL import Image, ImageTk
from io import BytesIO
import tempfile
import subprocess

from ciphers import apply  

HOST = "127.0.0.1"
PORT = 5000

def open_with_os(path):
    if sys.platform.startswith("win"):
        os.startfile(path)
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])

class ClientGUI:
    def __init__(self, root):
        self.root = root
        root.title("Client (İstemci)")
        root.geometry("760x620")

        top = tk.Frame(root); top.pack(fill="x", padx=8, pady=6)
        tk.Label(top, text="Sunucu IP:").pack(side="left")
        self.host_e = tk.Entry(top, width=15); self.host_e.insert(0, HOST); self.host_e.pack(side="left", padx=4)
        tk.Label(top, text="Port:").pack(side="left")
        self.port_e = tk.Entry(top, width=6); self.port_e.insert(0, str(PORT)); self.port_e.pack(side="left", padx=4)
        tk.Button(top, text="Bağlan", command=self.connect_server).pack(side="left", padx=6)
        self.status = tk.Label(top, text="Durum: Bağlı değil")
        self.status.pack(side="left", padx=10)

        mid = tk.Frame(root); mid.pack(fill="both", expand=True, padx=8, pady=6)
        self.log = scrolledtext.ScrolledText(mid, height=14, state="disabled")
        self.log.pack(fill="both", expand=True)

        self.image_label = tk.Label(root)
        self.image_label.pack(pady=8)

        bottom = tk.Frame(root); bottom.pack(fill="x", padx=8, pady=6)
        tk.Label(bottom, text="Sunucuya mesaj:").pack(anchor="w")

        
        opts = tk.Frame(bottom); opts.pack(fill="x", pady=4)

        tk.Label(opts, text="Algoritma:").pack(side="left")
        self.cipher_var = tk.StringVar(value="caesar")
        tk.OptionMenu(
            opts,
            self.cipher_var,
            "caesar",
            "substitution",
            "playfair",
            "vigenere",
            "rail_fence",
            "route_cipher",
            "columnar_transposition",
            "polybius",
            "pigpen",
            "affine",
            "vernam",
            "hill"
        ).pack(side="left", padx=6)

        tk.Label(opts, text="Key:").pack(side="left")
        self.key_e = tk.Entry(opts, width=26)
        self.key_e.insert(0, "3")  
        self.key_e.pack(side="left", padx=6)

        self.mode_var = tk.StringVar(value="enc")
        tk.Radiobutton(opts, text="Şifrele", variable=self.mode_var, value="enc").pack(side="left", padx=6)
        tk.Radiobutton(opts, text="Çöz", variable=self.mode_var, value="dec").pack(side="left", padx=6)

        row = tk.Frame(bottom); row.pack(fill="x")
        self.entry = tk.Entry(row)
        self.entry.pack(side="left", fill="x", expand=True)
        tk.Button(row, text="Gönder", command=self.send_text).pack(side="left", padx=6)
        tk.Button(row, text="Dosya Gönder (resim/ses/video)", command=self.send_file).pack(side="left", padx=6)

        self.sock = None
        self.reader_thread = None

    def log_write(self, s):
        self.log.configure(state="normal")
        self.log.insert("end", s + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def connect_server(self):
        host = self.host_e.get().strip() or "127.0.0.1"
        port = int(self.port_e.get().strip() or "5000")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, port))
            self.status.config(text=f"Durum: Bağlandı {host}:{port}")
            self.log_write(f"[+] Sunucuya bağlanıldı: {host}:{port}")
            self.reader_thread = threading.Thread(target=self.reader_loop, daemon=True)
            self.reader_thread.start()
        except Exception as e:
            messagebox.showerror("Bağlantı Hatası", str(e))

    def reader_loop(self):
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
                    self.log_write(f"[SUNUCU] ({cipher}/{mode}) {data}")

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
                        save_path = os.path.join(tmpdir, f"client_recv{ext}")
                        with open(save_path, "wb") as f:
                            f.write(data)
                        self.log_write(f"[DOSYA] Kaydedildi: {save_path} ({mimetype})")
                        open_with_os(save_path)
                else:
                    self.log_write(f"[!] Bilinmeyen tür: {typ}")

        except Exception as e:
            self.log_write(f"[HATA] {e}")
        finally:
            if self.sock:
                try: self.sock.close()
                except: pass

    def recvall(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def send_text(self):
        if not self.sock:
            messagebox.showwarning("Uyarı", "Önce bağlanın.")
            return

        msg = self.entry.get().strip()
        if not msg:
            return

        cipher = self.cipher_var.get().strip()
        key = self.key_e.get().strip()
        mode = self.mode_var.get().strip()

        try:
            out_msg = apply(cipher, mode, msg, key)
        except Exception as e:
            messagebox.showerror("Şifreleme Hatası", str(e))
            return

        body = out_msg.encode("utf-8")
        header = json.dumps({
            "type": "text",
            "size": len(body),
            "cipher": cipher,
            "mode": mode
        }).encode("utf-8")

        packet = struct.pack(">I", len(header)) + header + body
        try:
            self.sock.sendall(packet)
            self.log_write(f"[İSTEMCİ] ({cipher}/{mode}) {out_msg}")
            self.entry.delete(0, "end")
        except Exception as e:
            messagebox.showerror("Gönderme Hatası", str(e))

    def send_file(self):
        if not self.sock:
            messagebox.showwarning("Uyarı", "Önce bağlanın.")
            return
        path = filedialog.askopenfilename(title="Dosya seç (resim/ses/video)")
        if not path:
            return
        with open(path, "rb") as f:
            data = f.read()
        filename = os.path.basename(path)
        mimetype, _ = mimetypes.guess_type(filename)
        if not mimetype:
            mimetype = "application/octet-stream"

        header = json.dumps({
            "type": "file",
            "filename": filename,
            "mimetype": mimetype,
            "size": len(data)
        }).encode("utf-8")

        packet = struct.pack(">I", len(header)) + header + data
        try:
            self.sock.sendall(packet)
            self.log_write(f"[İSTEMCİ] Dosya gönderildi: {filename} ({mimetype}, {len(data)} bayt)")
        except Exception as e:
            messagebox.showerror("Gönderme Hatası", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientGUI(root)
    root.mainloop()
