import atexit
import threading

import jinja2

import rfc3986

import BaseHTTPServer
import SocketServer


class CaCertServerContext(object):
    def __init__(self, cacert_path):
        self.cacert_path = cacert_path
        self._cacert_content = None
        self._cacert_install = None

    def get_cacert_bytes(self):
        if self._cacert_content is None:
            with open(self.cacert_path) as f:
                self._cacert_content = f.read()
        return self._cacert_content

    def get_cacert_install_bytes(self):
        ca_cert = self.get_cacert_bytes()
        if self._cacert_install is None:
            loader = jinja2.PackageLoader(__package__)
            env = jinja2.Environment(loader=loader)
            vars = {'ca_cert': ca_cert.decode('ascii')}
            conf = env.get_template('cacert.sh.jinja2').render(**vars)
            self._cacert_install = conf.encode('utf-8')
        return self._cacert_install


class CaCertServer(SocketServer.TCPServer):
    def __init__(self, server_address, RequestHandlerClass, context):
        self.allow_reuse_address = True
        SocketServer.TCPServer.__init__(self,
                                        server_address,
                                        RequestHandlerClass)
        self.context = context


class CaCertHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(500)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(
            "HEAD method not supported; use GET method".encode('utf-8'))
        self.wfile.close()

    def do_GET(self):
        url = rfc3986.urlparse(self.path)
        if url.path in ('/', ''):
            self.send_response(200)
            self.send_header("Content-type", "application/x-x509-ca-cert")
            self.end_headers()
            self.wfile.write(self.server.context.get_cacert_bytes())
            self.wfile.close()
        elif url.path in ('/install/', '/install'):
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(self.server.context.get_cacert_install_bytes())
            self.wfile.close()
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write("Resource not found; please load /.")
            self.wfile.close()


def stop_cacertserver(server):
    print "Stopping server"
    if server is not None:
        server.shutdown()


def run_cacertserver(cacert_path, listen_port):
    server = CaCertServer(('', listen_port), CaCertHandler,
                          CaCertServerContext(cacert_path))
    t = threading.Thread(target=server.serve_forever)
    atexit.register(stop_cacertserver, server)
    t.setDaemon(True)
    t.start()
    return t
