import json
import os.path
import socket


def get_host_ip():
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        if s is not None:
            s.close()
    return ip


if __name__ == "__main__":
    ip = get_host_ip()
    with open(os.path.join("src", "ip.json"), 'w') as f_out:
        f_out.write(json.dumps(ip))
        f_out.flush()
