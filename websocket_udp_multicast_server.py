import websocket
import socket

WS_URL = "wss://stream.binance.com:9443/ws/btcusdt@trade"
MCAST_GRP = '224.1.1.1'
MCAST_PORT = 5007

def on_message(ws, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.sendto(message.encode('utf-8'), (MCAST_GRP, MCAST_PORT))
    print("Veri gönderildi:", message)

def run_websocket():
    ws = websocket.WebSocketApp(WS_URL, on_message=on_message)
    ws.run_forever()

if __name__ == "__main__":
    run_websocket()