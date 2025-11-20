import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import threading
import socket
import os
import time
from datetime import datetime

CHUNK_SIZE = 4096

class PacketApp:
    def __init__(self, root):
        self.root = root
        root.title("Packet Sender / Receiver")
        root.geometry("820x620")

        # Sender frame
        sf = tk.LabelFrame(root, text="Sender", padx=6, pady=6)
        sf.pack(fill="x", padx=8, pady=6)

        tk.Label(sf, text="Protocol:").grid(row=0, column=0, sticky="w")
        self.proto = tk.StringVar(value="UDP")
        tk.Radiobutton(sf, text="UDP", variable=self.proto, value="UDP").grid(row=0, column=1, sticky="w")
        tk.Radiobutton(sf, text="TCP", variable=self.proto, value="TCP").grid(row=0, column=2, sticky="w")

        tk.Label(sf, text="Target IP:").grid(row=1, column=0, sticky="w")
        self.target_ip = tk.Entry(sf, width=20); self.target_ip.grid(row=1, column=1, sticky="w")
        self.target_ip.insert(0, "127.0.0.1")

        tk.Label(sf, text="Target Port:").grid(row=1, column=2, sticky="w")
        self.target_port = tk.Entry(sf, width=8); self.target_port.grid(row=1, column=3, sticky="w")
        self.target_port.insert(0, "5007")

        tk.Label(sf, text="File to send:").grid(row=2, column=0, sticky="w")
        self.file_entry = tk.Entry(sf, width=60); self.file_entry.grid(row=2, column=1, columnspan=3, sticky="w")
        tk.Button(sf, text="Browse...", command=self.browse_file).grid(row=2, column=4, sticky="w")

        tk.Label(sf, text="Send folder (receiver saves here):").grid(row=3, column=0, sticky="w")
        self.save_folder = tk.Entry(sf, width=60); self.save_folder.grid(row=3, column=1, columnspan=3, sticky="w")
        tk.Button(sf, text="Choose...", command=self.choose_folder).grid(row=3, column=4, sticky="w")

        tk.Button(sf, text="Send", bg="#4CAF50", fg="white", command=self.start_send).grid(row=4, column=1, pady=8)
        tk.Button(sf, text="Clear Log", command=self.clear_log).grid(row=4, column=2, pady=8)

        # Receiver frame
        rf = tk.LabelFrame(root, text="Receiver", padx=6, pady=6)
        rf.pack(fill="x", padx=8, pady=6)

        tk.Label(rf, text="Bind IP:").grid(row=0, column=0, sticky="w")
        self.bind_ip = tk.Entry(rf, width=20); self.bind_ip.grid(row=0, column=1, sticky="w")
        self.bind_ip.insert(0, "0.0.0.0")

        tk.Label(rf, text="Bind Port:").grid(row=0, column=2, sticky="w")
        self.bind_port = tk.Entry(rf, width=8); self.bind_port.grid(row=0, column=3, sticky="w")
        self.bind_port.insert(0, "5007")

        self.start_btn = tk.Button(rf, text="Start Receiver", bg="#2196F3", fg="white", command=self.toggle_receiver)
        self.start_btn.grid(row=1, column=1, pady=8)
        tk.Button(rf, text="Open Save Folder", command=self.open_save_folder).grid(row=1, column=2)

        # Log area
        tk.Label(root, text="Log:").pack(anchor="w", padx=10)
        self.logbox = scrolledtext.ScrolledText(root, state="disabled", height=20)
        self.logbox.pack(fill="both", expand=True, padx=8, pady=6)

        # State
        self.receiver_thread = None
        self.receiver_stop = threading.Event()

    def log(self, msg):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{ts}] {msg}\n"
        self.logbox.configure(state="normal")
        self.logbox.insert(tk.END, entry)
        self.logbox.yview(tk.END)
        self.logbox.configure(state="disabled")

    def clear_log(self):
        self.logbox.configure(state="normal")
        self.logbox.delete("1.0", tk.END)
        self.logbox.configure(state="disabled")

    def browse_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, p)

    def choose_folder(self):
        d = filedialog.askdirectory()
        if d:
            self.save_folder.delete(0, tk.END)
            self.save_folder.insert(0, d)

    def open_save_folder(self):
        folder = self.save_folder.get() or os.getcwd()
        if os.path.isdir(folder):
            if os.name == "nt":
                os.startfile(folder)
            else:
                try:
                    import subprocess
                    subprocess.Popen(["xdg-open", folder])
                except Exception:
                    pass
        else:
            messagebox.showwarning("Uyarı", "Geçerli bir klasör seçin.")

    def start_send(self):
        filepath = self.file_entry.get()
        if not filepath or not os.path.isfile(filepath):
            messagebox.showerror("Hata", "Gönderilecek dosyayı seçin.")
            return
        try:
            port = int(self.target_port.get())
        except Exception:
            messagebox.showerror("Hata", "Geçerli bir hedef port girin.")
            return
        proto = self.proto.get()
        t = threading.Thread(target=self.send_file, args=(proto, self.target_ip.get(), port, filepath), daemon=True)
        t.start()

    def send_file(self, proto, ip, port, path):
        self.log(f"Başlatılıyor: {proto} -> {ip}:{port} dosya={os.path.basename(path)}")
        try:
            filesize = os.path.getsize(path)
            sent = 0
            if proto == "UDP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                with open(path, "rb") as f:
                    seq = 0
                    while True:
                        chunk = f.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        # simple header: seq(4 bytes) + length(4 bytes) optional
                        header = seq.to_bytes(4, "big") + len(chunk).to_bytes(4, "big")
                        sock.sendto(header + chunk, (ip, port))
                        sent += len(chunk)
                        self.log(f"UDP gönderildi: seq={seq} bytes={len(chunk)} ({sent}/{filesize})")
                        seq += 1
                        time.sleep(0.001)
                sock.close()
            else:  # TCP
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((ip, port))
                with open(path, "rb") as f:
                    while True:
                        chunk = f.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        sock.sendall(chunk)
                        sent += len(chunk)
                        self.log(f"TCP gönderildi: bytes={len(chunk)} ({sent}/{filesize})")
                sock.shutdown(socket.SHUT_WR)
                sock.close()
            self.log(f"Gönderim tamamlandı: {os.path.basename(path)}")
        except Exception as e:
            self.log(f"Gönderim hatası: {e}")

    def toggle_receiver(self):
        if self.receiver_thread and self.receiver_thread.is_alive():
            self.stop_receiver()
        else:
            self.start_receiver()

    def start_receiver(self):
        try:
            bind_ip = self.bind_ip.get()
            bind_port = int(self.bind_port.get())
        except Exception:
            messagebox.showerror("Hata", "Geçerli bir bind port girin.")
            return
        folder = self.save_folder.get() or os.getcwd()
        if not os.path.isdir(folder):
            messagebox.showerror("Hata", "Geçerli bir kayıt klasörü seçin.")
            return
        self.receiver_stop.clear()
        self.receiver_thread = threading.Thread(target=self.receiver_loop, args=(bind_ip, bind_port, folder), daemon=True)
        self.receiver_thread.start()
        self.start_btn.config(text="Stop Receiver", bg="#f44336")
        self.log(f"Receiver başlatıldı: {bind_ip}:{bind_port} -> {folder}")

    def stop_receiver(self):
        self.receiver_stop.set()
        self.start_btn.config(text="Start Receiver", bg="#2196F3")
        self.log("Receiver durduruluyor...")

    def receiver_loop(self, bind_ip, bind_port, folder):
        # UDP and TCP both supported: create UDP socket and TCP listener
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            udp_sock.bind((bind_ip, bind_port))
        except Exception as e:
            self.log(f"UDP bind hatası: {e}")
            return

        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            tcp_sock.bind((bind_ip, bind_port))
            tcp_sock.listen(5)
        except Exception as e:
            self.log(f"TCP bind/hop hatası: {e}")
            tcp_sock.close()
            # keep UDP if TCP failed

        udp_sock.setblocking(False)
        tcp_sock.setblocking(False)

        self.log("Receiver döngüsü çalışıyor (UDP ve TCP aynı port üzerinde).")

        conn_list = []
        while not self.receiver_stop.is_set():
            # UDP receive
            try:
                data, addr = udp_sock.recvfrom(65536)
                if data:
                    # if we used header (seq+len) strip it if present
                    if len(data) > 8:
                        seq = int.from_bytes(data[0:4], "big")
                        length = int.from_bytes(data[4:8], "big")
                        payload = data[8:8+length]
                        fname = f"udp_{addr[0]}_{addr[1]}_{seq}_{int(time.time())}.bin"
                    else:
                        payload = data
                        fname = f"udp_{addr[0]}_{addr[1]}_{int(time.time())}.bin"
                    path = os.path.join(folder, fname)
                    with open(path, "ab") as out:
                        out.write(payload)
                    self.log(f"UDP alındı {addr} -> kaydedildi {fname} ({len(payload)} bytes)")
            except BlockingIOError:
                pass
            except Exception as e:
                self.log(f"UDP alım hatası: {e}")

            # TCP accept
            try:
                conn, addr = tcp_sock.accept()
                conn.settimeout(1.0)
                self.log(f"TCP bağlantı kabul edildi: {addr}")
                conn_list.append((conn, addr, int(time.time())))
            except BlockingIOError:
                pass
            except Exception as e:
                self.log(f"TCP accept hatası: {e}")

            # handle tcp connections
            for c, addr, start_ts in conn_list[:]:
                try:
                    chunk = c.recv(65536)
                    if chunk:
                        fname = f"tcp_{addr[0]}_{addr[1]}_{start_ts}.bin"
                        path = os.path.join(folder, fname)
                        with open(path, "ab") as out:
                            out.write(chunk)
                        self.log(f"TCP alındı {addr} -> kaydedildi {fname} ({len(chunk)} bytes)")
                    else:
                        c.close()
                        conn_list.remove((c, addr, start_ts))
                        self.log(f"TCP bağlantı kapandı: {addr}")
                except socket.timeout:
                    pass
                except Exception as e:
                    try:
                        c.close()
                    except:
                        pass
                    try:
                        conn_list.remove((c, addr, start_ts))
                    except:
                        pass
                    self.log(f"TCP bağlantı hatası {addr}: {e}")

            time.sleep(0.01)

        # cleanup
        for c, addr, _ in conn_list:
            try:
                c.close()
            except:
                pass
        try:
            udp_sock.close()
        except:
            pass
        try:
            tcp_sock.close()
        except:
            pass
        self.log("Receiver durduruldu.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketApp(root)
    root.mainloop()