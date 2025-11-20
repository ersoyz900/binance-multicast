import websocket
import socket
import logging
import ssl
import time
import traceback

WS_URL = "wss://stream.binance.com:9443/ws/btcusdt@trade"
MCAST_GRP = '224.1.1.1'
MCAST_PORT = 5007

# UDP soketini bir kez oluştur
udp_sock = None
def create_udp_socket():
    global udp_sock
    if udp_sock:
        return udp_sock
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        # TTL integer works on most platforms
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        udp_sock = s
        return udp_sock
    except Exception:
        print("UDP soket oluşturulurken hata:")
        traceback.print_exc()
        return None

def on_message(ws, message):
    try:
        s = create_udp_socket()
        if s is None:
            print("UDP soket yok, veri gönderilemedi.")
            return
        if isinstance(message, str):
            data = message.encode('utf-8')
        else:
            data = message
        s.sendto(data, (MCAST_GRP, MCAST_PORT))
        print("Veri gönderildi. Uzunluk:", len(data))
    except Exception:
        print("UDP gönderme hatası:")
        traceback.print_exc()

def on_error(ws, error):
    print("WebSocket hata:", error)
    traceback.print_exc()

def on_close(ws, close_status_code, close_msg):
    print("WebSocket kapandı:", close_status_code, close_msg)

def on_open(ws):
    print("WebSocket açıldı.")

def run_websocket():
    websocket.enableTrace(True)
    logging.basicConfig(level=logging.DEBUG)
    while True:
        ws = websocket.WebSocketApp(
            WS_URL,
            on_open=on_open,
            on_message=on_message,
            on_error=on_error,
            on_close=on_close
        )
        try:
            # ping ayarları ve sertifika doğrulaması
            ws.run_forever(sslopt={"cert_reqs": ssl.CERT_REQUIRED}, ping_interval=30, ping_timeout=10)
        except Exception:
            print("run_forever sırasında hata:")
            traceback.print_exc()
        print("Bağlantı kesildi, 5 sn sonra yeniden bağlanılıyor...")
        time.sleep(5)

if __name__ == "__main__":
    run_websocket()