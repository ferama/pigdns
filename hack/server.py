from http.server import HTTPServer, BaseHTTPRequestHandler 
import ssl

port = 443

class HelloHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write("Hey, it's working!".encode("utf-8"))

if __name__ == "__main__":
    httpd = HTTPServer(('0.0.0.0', port), HelloHandler)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("./fullchain.pem", "./privkey.pem")

    httpd.socket = ctx.wrap_socket(
        httpd.socket,
        server_side=True)

    try:
        print("Listening on :" + str(port))
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
