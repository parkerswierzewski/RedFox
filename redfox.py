"""
RedFox v1.0

author: Parker J Swierzewski
language: python3
desc: RedFox was created for my CSEC 380 Principles of Web Application Security course where we needed to create
        our own user-agent. RedFox is mainly for sending and handling HTTP requests with the use of sockets. The
        program supports SSL/TLS. It only supports error checking for errors I have encountered while running it.
"""
import socket
import ssl
import urllib.parse

class RedFox:
    def __init__(self, host, path="/", port=80, agent="Mozilla/5.0", ssl=False):
        """
        This function will initialize a RedFox object with the given parameters.

        :param host: The host you're sending the request to.
        :param path: The path being requested (i.e. "/about-rit" for https://rit.edu/about-rit).
        :param port: The port the host is on (Port 80 by default).
        :param agent: The user agent (Mozilla/5.0 by default).
        :param ssl: Whether or not SSL/TLS support is needed (False by default, but if port 443 is being used it will be turned on).
        """
        self.host = str(host)
        self.path = str(path)

        if ssl or port == 443:
            self.url = "https://" + host + path
        else:
            self.url = "http://" + host + path

        self.port = port
        self.agent = agent

        self.ssl = ssl
        if port == 443:
            self.ssl = True

        self.content = "application/x-www-form-urlencoded"

    def build_request(self, request_type="GET", path="", connection="close", body=""):
        """
        This function will build and properly format a HTTP request.

        :param request_type: The type of HTTP request (GET by default).
        :param path: The resource attempting to be accessed.
        :param connection: The type of connection (Close by default).
        :param body: Additional data for the body of the request (Nothing by default).
        :return: The properly formatted request.
        """
        if path == "" or path is None:
            path = self.url

        # Building a HTTP request as done in Homework 2.
        self.request = "%s %s HTTP/1.1\r\n" \
                       "Host: %s:%d\r\n" \
                       "Accept: */*\r\n" \
                       "Accept-Language: en-US\r\n" \
                       "User-Agent: %s\r\n" \
                       "Connection: %s\r\n" \
                       "Content-Type: %s\r\n" \
                       "Content-Length: %d\r\n\r\n%s"  % \
                       (request_type, path, self.host, self.port, self.agent, connection, self.content, len(body), urllib.parse.quote_plus(str(body)))

        return self.request

    def handle_request(self, timeout=0, encode="utf-8", decode=True):
        """
        This function will send and receive requests sent over a socket.

        :param timeout: The time in seconds the socket should close if no response is received.
        :param encode: The type of encoding (UTF-8 encoding by default).
        :param decode: Whether or not the response should be decoded or not (Decoded by default).
        :return: The data that was received (A return of -1 means something went wrong).
        """
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Sets a timeout.
        if timeout > 0:
            self.client.settimeout(timeout)

        # This if statement is for SSL/TLS support.
        # https://docs.python.org/3/library/ssl.html#ssl.SSLContext.wrap_socket
        if self.ssl or self.port == 443:
            self.client = ssl.wrap_socket(self.client)

        # Connect to the given host and port.
        try:
            self.client.connect((self.host, self.port))
        except ConnectionRefusedError as e:
            print("\n[!] RedFox could not connect to %s. \n[!] Error: %s\n" % (self.host, e))
            return -1
        except socket.gaierror as e:
            print("\n[!] RedFox could not connect to %s. Are you sure you entered it correctly? \n[!] Error: %s\n" % (self.host, e))
            return -1

        self.client.sendall(self.request.encode(encode))

        # Obtains all the data received.
        self.data = b''
        while True:
            response = self.client.recv(1024)
            if not response:
                break
            else:
                self.data += response

        # Properly closes the socket
        self.client.close()

        # Attempts to decode the response.
        if decode:
            try:
                self.data = self.data.decode(encode)
            except UnicodeDecodeError as error:
                print("\n[!] RedFox could not decode the response! \n[!] Error: %s\n" % error)

        return self.data

# Used to return error codes and their titles.
# Please note this does not include all error codes
HTTP_CODES = {200:"OK", 301:"Moved Permanently", 302:"Found", 400:"Bad Request", 403:"Forbidden", 404:"Not Found"}

def get_response(response):
    """
    This function will return the HTTP response code from
    the server.

    :param response: The response from the server.
    :return: The HTTP response code.
    """
    code = str(response.split()[1])

    if int(code) not in HTTP_CODES:
        return "<HTTP Response: " + code + ">"
    return "<HTTP Response: " + code + " " + HTTP_CODES[int(code)] + ">"

def has_response(response, code="200 OK"):
    """
    This function will check if an HTTP code is in a response from
    the server.

    :param response: The response/data received from the server.
    :param code: The HTTP code you're looking for (200 by default).
    :return: Boolean Flag (True = Found code).
    """
    if code in str(response):
        return True
    return False

def get_redirect(response):
    """
    This function will obtain the redirect link given when
    a 301 or 302 error has occurred.

    :param response: The response/data received from the server.
    :return: The redirect link (A return of -1 means nothing was found
                and a return of 0 means the response wasn't a 301 or 302).
    """
    if has_response(response, code="301 Moved Permanently") or has_response(response, code="302 Found"):
        redirect = ""
        data = response.split()

        position = 0
        for element in data:
            if "Location:" in element:
                redirect = element[position+1]
                break
            position += 1

        if redirect == "":
            return -1

        return redirect

    return 0

def get_depth(weburl):
    """
    This function will get the depth of the given url.

    For example rit.edu/study/undergraduate has a depth
    of two.

    :param weburl: The current url.
    :return: The depth as an integer.
    """
    s = weburl.split("/")

    if "http:" or "https:" in weburl:
        if s[-1] == "" or s[-1] is None:
            s.pop()
        return (len(s) - 3)
    else:
        return (len(s) - 1)

def blacklist(weburl, domain):
    """
    This function will check if the url given is within the domain.

    For example library.rit.edu is within the rit.edu domain, but
        apple.com is not within the rit.edu domain.

    :param weburl: The url.
    :param domain: The domain.
    :return: Boolean Flag (True = Within domain).
    """
    if domain not in weburl:
        return False
    return True

# more to come later :3
