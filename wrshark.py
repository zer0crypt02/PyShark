import tkinter as tk
from scapy.all import sniff
import threading
import time

class NetworkSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ağ Dinleme Uygulaması")

        # Pencereyi ekranın ortasına yerleştir
        self.center_window()

        # Ağı dinle butonu
        self.listen_button = tk.Button(root, text="Ağı Dinle", command=self.start_sniffing)
        self.listen_button.pack(pady=10)

        # Dinleme sonucu Text widget'ı, daha büyük boyut
        self.result_text = tk.Text(root, width=80, height=20, wrap=tk.WORD, state=tk.DISABLED)
        self.result_text.pack(pady=20)

    def center_window(self):
        # Ekranın boyutlarını al
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        # Pencere boyutlarını al
        window_width = 600  # İstediğiniz pencere genişliği
        window_height = 400  # İstediğiniz pencere yüksekliği

        # Ekranın ortasına yerleştirme hesaplaması
        position_top = int(screen_height / 2 - window_height / 2)
        position_right = int(screen_width / 2 - window_width / 2)

        # Pencereyi ekranın ortasına yerleştir
        self.root.geometry(f'{window_width}x{window_height}+{position_right}+{position_top}')

    def start_sniffing(self):
        # Dinlemeyi başlat
        self.result_text.config(state=tk.NORMAL)  # Text widget'ını düzenlenebilir yap
        self.result_text.delete(1.0, tk.END)  # Eski metinleri temizle
        self.result_text.insert(tk.END, "Ağ dinleniyor...\n")
        self.result_text.config(state=tk.DISABLED)  # Text widget'ını tekrar yalnızca görüntülenebilir yap
        sniff_thread = threading.Thread(target=self.sniff_network)
        sniff_thread.daemon = True  # Uygulama kapanırken bu iş parçacığı da sonlansın
        sniff_thread.start()

    def sniff_network(self):
        # Ağı dinleyip, gelen trafiği analiz et
        def packet_callback(packet):
            if packet.haslayer('IP'):
                ip_src = packet['IP'].src
                ip_dst = packet['IP'].dst
                new_text = f"{ip_src} --> {ip_dst}\n"

                # Eğer HTTP trafiği varsa, Host bilgisi göster
                if packet.haslayer('Raw'):
                    payload = packet.getlayer('Raw').load
                    if b'Host' in payload:  # HTTP Host başlığı
                        host = payload.split(b'Host: ')[1].split(b'\r\n')[0]
                        new_text += f"Web Sitesi: {host.decode('utf-8')}\n"

                # Metni ekle
                self.result_text.config(state=tk.NORMAL)  # Text widget'ını düzenlenebilir yap
                self.result_text.insert(tk.END, new_text)  # Yeni metni ekle
                self.result_text.yview(tk.END)  # Kaydırmayı en alta yap
                self.result_text.config(state=tk.DISABLED)  # Text widget'ını tekrar yalnızca görüntülenebilir yap

                # Her yeni metinden sonra 0.5 saniye bekle
                time.sleep(0.5)

        sniff(prn=packet_callback, store=0, count=0)  # Sonsuz paket dinle

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkSnifferApp(root)
    root.mainloop()
