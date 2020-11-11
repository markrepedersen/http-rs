mod parse;

use {
    cookie_factory::{combinator::string, gen, multi::all, sequence::tuple, SerializeFn},
    flate2::bufread::{DeflateDecoder, GzDecoder, ZlibDecoder},
    nom::{
        bytes::{
            streaming::take_till,
            streaming::{tag, take_while},
        },
        character::{
            is_alphabetic,
            streaming::{crlf, digit1, space1},
        },
        error::context,
        multi::many_till,
        sequence::{preceded, terminated},
    },
    parse::{Input, ParseResult},
    rustls::{ClientConfig, ClientSession, Stream},
    std::{
        collections::HashMap,
        error::Error,
        fmt::{Debug, Display},
        io::{self, ErrorKind::ConnectionAborted},
        io::{Read, Write},
        net::TcpStream,
        str::{from_utf8, from_utf8_unchecked, FromStr},
        string::ToString,
        sync::Arc,
    },
    strum_macros::{Display, EnumString},
    webpki::DNSNameRef,
    webpki_roots::TLS_SERVER_ROOTS,
    CommonHeaders::*,
    CtrlChars::Colon,
    CtrlChars::CR,
};

// -------------- UTILS --------------------

/**
 * Unicode Hexadecimal values for some common control characters.
 */
pub enum CtrlChars {
    Space = 0x20,
    CR = 0x0D,
    LF = 0x0A,
    Colon = 0x3A,
    ForwardSlash = 0x2F,
    BackSlash = 0x5C,
}

/**
 * Header keys.
 */
#[derive(Debug, Display, PartialEq, EnumString, Eq)]
pub enum CommonHeaders {
    #[strum(serialize = "HOST")]
    Host,
    #[strum(serialize = "CONNECTION")]
    Connection,
    #[strum(serialize = "ACCEPT")]
    Accept,
    #[strum(serialize = "ACCEPT-ENCODING")]
    AcceptEncoding,
    #[strum(serialize = "CONTENT-TYPE")]
    ContentType,
    #[strum(serialize = "CONTENT-LENGTH")]
    ContentLength,
    #[strum(serialize = "CONTENT-ENCODING")]
    ContentEncoding,
}

/**
 * Serialize to binary the CRLF control character.
 */
pub fn serialize_crlf<'a, W: io::Write + 'a>() -> impl SerializeFn<W> + 'a {
    string("\r\n")
}

/**
 * Serialize to binary the space character.
 */
pub fn serialize_space<'a, W: io::Write + 'a>() -> impl SerializeFn<W> + 'a {
    string(" ")
}

#[derive(Display, Debug, PartialEq)]
pub enum Protocol {
    // The default protocol for requests.
    HTTP,
    // HTTP over TLS.
    HTTPS,
}

//-------------- REQUEST ------------------
#[derive(Debug)]
pub struct Request<'a> {
    pub method: Method,
    pub protocol: Protocol,
    pub host: Option<&'a str>,
    pub path: &'a str,
    pub port: Option<u16>,
    pub version: &'a str,
    pub headers: Headers,
    pub body: Option<Body>,
}

impl<'a> Request<'a> {
    /**
    Send the request over HTTPS.
    */
    fn send_https(
        mut socket: &TcpStream,
        mut buf: &mut Vec<u8>,
        host: &str,
    ) -> Result<(), io::Error> {
        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&TLS_SERVER_ROOTS);

        let config = Arc::new(config);
        let dns = DNSNameRef::try_from_ascii_str(host).unwrap();
        let mut client = ClientSession::new(&config, dns);
        let mut tls_stream = Stream::new(&mut client, &mut socket);

        tls_stream.write_all(&mut buf)?;
        buf.clear();

        if let Err(e) = tls_stream.read_to_end(&mut buf) {
            if e.kind() != ConnectionAborted {
                return Err(e);
            }
        }

        Ok(())
    }

    fn send_http(mut socket: &TcpStream, buf: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
        socket.write_all(buf)?;
        buf.clear();
        socket.read_to_end(buf)?;

        Ok(())
    }

    /**
     * Send the request.
     */
    pub fn send(&self) -> Result<Response, Box<dyn Error>> {
        match self.host {
            Some(host) => {
                let port = if let Some(port) = self.port { port } else { 80 };
                let socket = TcpStream::connect(format!("{}:{}", host, port))?;
                let buf = Vec::new();
                let (mut buf, _) = gen(self.serialize(), buf)?;

                if self.protocol == Protocol::HTTPS {
                    Self::send_https(&socket, &mut buf, host)?;
                } else {
                    Self::send_http(&socket, &mut buf)?;
                }

                Ok(Response::parse(&mut buf).unwrap())
            }
            None => panic!("No URL provided."),
        }
    }

    /**
     * Create a default request.
     */
    pub fn default() -> Self {
        Self {
            method: Method::GET,
            path: "/",
            protocol: Protocol::HTTP,
            host: None,
            port: Some(80),
            version: "HTTP/1.1",
            headers: Headers::new(),
            body: None,
        }
    }

    /**
     * Notify the server that this request contains basic authentication.
     */
    pub fn basic_auth(&mut self, username: &'a str, password: &'a str) -> &mut Self {
        self.header(username, password);
        self
    }

    /**
     * Notify the server that this connection should remain open until the client closes it.
     */
    pub fn keep_alive(&mut self) -> &mut Self {
        self.header("CONNECTION", "keep-alive");
        self
    }

    /**
     * Set the host of the request.
     */
    pub fn host(&mut self, host: &'a str) -> &mut Self {
        self.host = Some(host);
        self.header("HOST", host);
        self
    }

    /**
    Enables HTTP over TLS.
     */
    pub fn https(&mut self) -> &mut Self {
        self.port = Some(443);
        self.protocol = Protocol::HTTPS;
        self
    }

    /**
     * Set the port of the request.
     */
    pub fn port(&mut self, port: u16) -> &mut Self {
        self.port = Some(port);
        self
    }

    /**
     * Set the HTTP request method. The default is GET.
     */
    pub fn method(&mut self, method: Method) -> &mut Self {
        self.method = method;
        self
    }

    /**
     * Set the server path.
     */
    pub fn path(&mut self, path: &'a str) -> &mut Self {
        self.path = path;
        self
    }

    /**
     * Add a header to this request.
     */
    pub fn header(&mut self, key: &'a str, val: &'a str) -> &mut Self {
        self.headers.insert(key, val);
        self
    }

    /**
     * Set the request's body.
     */
    pub fn body(&mut self, i: Input<'a>) -> &mut Self {
        self.body = Body::parse(i, None).ok().map(|(_, body)| body);
        self
    }

    /**
     * Parse a request from a stream of bytes.
     */
    pub fn parse(i: Input<'a>) -> Result<Self, Box<dyn Error + 'a>> {
        let (_, req) = context("Request", |i| {
            let (i, method) = Method::parse(i)?;
            let (i, path) = preceded(space1, take_till(|c| c == CtrlChars::Space as u8))(i)?;
            let (i, version) = preceded(space1, terminated(take_till(|c| c == CR as u8), crlf))(i)?;
            let (i, headers) = Headers::parse(i)?;
            let (i, body) = match headers.get(&ContentLength.to_string()) {
                Some(len) => {
                    let (i, body) = Body::parse(i, len.parse().ok())?;
                    (i, Some(body))
                }
                None => (i, None),
            };
            let res = Self {
                method,
                path: from_utf8(path).unwrap(),
                protocol: Protocol::HTTP,
                host: None,
                port: None,
                version: from_utf8(version).unwrap(),
                headers,
                body,
            };

            Ok((i, res))
        })(i)?;

        Ok(req)
    }

    fn serialize<W: io::Write + 'a>(&'a self) -> impl SerializeFn<W> + 'a {
        tuple((
            self.method.serialize(),
            serialize_space(),
            string(self.path),
            serialize_space(),
            string(self.version),
            serialize_crlf(),
            self.headers.serialize(),
            serialize_crlf(),
        ))
    }
}

#[derive(Debug, Display, PartialEq, EnumString, Eq)]
pub enum Method {
    OPTIONS,
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    TRACE,
    CONNECT,
}

impl Method {
    pub fn serialize<'a, W: io::Write + 'a>(&'a self) -> impl SerializeFn<W> + 'a {
        string(self.to_string())
    }

    pub fn parse(i: Input) -> ParseResult<Self> {
        context("Method", |i| {
            let (i, method) = take_while(is_alphabetic)(i)?;
            let res = match Method::from_str(from_utf8(method).unwrap()) {
                Ok(method) => method,
                Err(_) => {
                    unsafe {
                        panic!(
                            "[UTF-8 decoding] Invalid HTTP method '{}'",
                            from_utf8_unchecked(method)
                        );
                    };
                }
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(Debug)]
pub struct Header {
    pub key: String,
    pub value: String,
}

impl Header {
    pub fn parse(i: Input) -> ParseResult<Self> {
        context("Header", |i| {
            let (i, key) = terminated(take_till(|c| c == Colon as u8), tag(b": "))(i)?;
            let (i, value) = terminated(take_till(|c| c == CR as u8), crlf)(i)?;
            let res = Self {
                key: from_utf8(key).unwrap().to_string().to_uppercase(),
                value: from_utf8(value).unwrap().to_string().to_uppercase(),
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(Debug)]
pub struct Headers {
    headers: HashMap<String, String>,
}

impl Headers {
    pub fn serialize<'a, W: io::Write + 'a>(&'a self) -> impl SerializeFn<W> + 'a {
        all(self
            .headers
            .iter()
            .map(|(key, val)| tuple((string(key), string(": "), string(val), serialize_crlf()))))
    }

    pub fn new() -> Self {
        Self {
            headers: HashMap::new(),
        }
    }

    pub fn parse(i: Input) -> ParseResult<Self> {
        context("Headers", |i| {
            let (i, (data, _)) = many_till(Header::parse, crlf)(i)?;
            let mut headers = HashMap::new();

            for header in data {
                headers.insert(header.key, header.value);
            }

            Ok((i, Self { headers }))
        })(i)
    }

    pub fn insert(&mut self, key: &str, val: &str) {
        self.headers.insert(key.to_string(), val.to_string());
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.headers.get(&key.to_string())
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.headers.contains_key(key)
    }
}

#[derive(Display, Debug)]
pub enum Body {
    Single(SinglePartBody),
    Multi(MultiPartBody),
}

impl Body {
    /**
     * Parse a binary input into request body format.
     * Takes a *len*, representing the *CONTENT-LENGTH* of the body.
     * If len is None, then parse until the end of the input. Otherwise, only parse *len* amount of it.
     */
    pub fn parse(i: Input, len: Option<usize>) -> ParseResult<Self> {
        context("Body", |i: Input| {
            let (i, body) = SinglePartBody::parse(i, len)?;
            Ok((i, Body::Single(body)))
        })(i)
    }
}

pub struct SinglePartBody {
    data: Vec<u8>,
}

impl Display for SinglePartBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", unsafe { from_utf8_unchecked(&self.data) })
    }
}

impl Debug for SinglePartBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#?}", unsafe { from_utf8_unchecked(&self.data) })
    }
}

impl SinglePartBody {
    pub fn decompress(&mut self, headers: &Headers) -> Result<&Self, Box<dyn Error>> {
        let old_buf = &self.data[..];
        let mut new_buf = Vec::new();
        let header = headers.get(&ContentEncoding.to_string());

        match header.map(|h| &h[..]) {
            Some("GZIP") => {
                let mut decoder = GzDecoder::new(old_buf);
                decoder.read_to_end(&mut new_buf)?;
                self.data = new_buf;
            }
            Some("DEFLATE") => {
                let mut decoder = DeflateDecoder::new(old_buf);
                decoder.read_to_end(&mut new_buf)?;
                self.data = new_buf;
            }
            Some("ZLIB") => {
                let mut decoder = ZlibDecoder::new(old_buf);
                decoder.read_to_end(&mut new_buf)?;
                self.data = new_buf;
            }
            Some(_) => unimplemented!("Unknown compression schema."),
            None => println!("Response body was not compressed"),
        };

        Ok(self)
    }

    pub fn parse(i: Input, len: Option<usize>) -> ParseResult<Self> {
        context("Single-part Body", |i: Input| {
            let data = if let Some(len) = len {
                &i[..len]
            } else {
                &i[..]
            };
            Ok((
                i,
                Self {
                    data: data.to_vec(),
                },
            ))
        })(i)
    }
}

#[derive(Debug)]
pub struct MultiPartBody {
    data: Vec<u8>,
}

// -------------------- RESPONSE---------------------

#[derive(Debug, PartialEq, EnumString, Eq)]
pub enum StatusCode {
    Success = 200,
    BadRequest = 400,
    NotFound = 404,
    MovedPermanently = 301,
}

impl StatusCode {
    pub fn from_str(i: Input) -> Option<Self> {
        use StatusCode::*;

        unsafe {
            match from_utf8_unchecked(i) {
                "200" => Some(Success),
                "400" => Some(BadRequest),
                "404" => Some(NotFound),
                "301" => Some(MovedPermanently),
                _ => None,
            }
        }
    }
}

impl StatusCode {
    pub fn parse(i: Input) -> ParseResult<Self> {
        context("Status Code", |i| {
            let (i, status_code) = terminated(digit1, space1)(i)?;
            let res = match StatusCode::from_str(status_code) {
                Some(method) => method,
                None => {
                    unsafe {
                        panic!(
                            "[UTF-8 decoding] Invalid HTTP status code '{}'.",
                            from_utf8_unchecked(status_code)
                        );
                    };
                }
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(Debug)]
pub struct ResponseStatus {
    pub protocol_version: String,
    pub status_code: StatusCode,
    pub description: String,
}

impl ResponseStatus {
    pub fn parse(i: Input) -> ParseResult<Self> {
        context("Status", |i| {
            let (i, protocol_version) =
                terminated(take_till(|c| c == CtrlChars::Space as u8), space1)(i)?;
            let (i, status_code) = StatusCode::parse(i)?;
            let (i, description) = terminated(take_till(|c| c == CR as u8), crlf)(i)?;
            let res = Self {
                protocol_version: from_utf8(protocol_version).unwrap().to_string(),
                status_code,
                description: from_utf8(description).unwrap().to_string(),
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(Debug)]
pub struct Response {
    pub status: ResponseStatus,
    pub headers: Headers,
    pub body: Option<Body>,
}

impl Response {
    pub fn parse<'a>(i: Input<'a>) -> Result<Self, Box<dyn Error + 'a>> {
        let (_, response) = context("Response", |i| {
            let (i, status) = ResponseStatus::parse(i)?;
            let (i, headers) = Headers::parse(i)?;
            let (i, body) = match headers.get(&ContentLength.to_string()) {
                Some(len) => {
                    let (i, body) = Body::parse(i, len.parse().ok())?;
                    (i, Some(body))
                }
                None => (i, None),
            };
            let res = Self {
                status,
                headers,
                body,
            };

            Ok((i, res))
        })(i)?;

        Ok(response)
    }
}

#[test]
fn test_parse_request() -> Result<(), Box<dyn Error>> {
    better_panic::install();

    let mut req_str = String::new();

    req_str.push_str("GET / HTTP/1.0");
    req_str.push_str("\r\n");
    req_str.push_str("Host: www.rust-lang.org");
    req_str.push_str("\r\n");
    req_str.push_str("Connection: close");
    req_str.push_str("\r\n");
    req_str.push_str("\r\n");

    let req_utf_8 = req_str.as_bytes();

    match Request::parse(req_utf_8) {
        Ok(req) => {
            assert_eq!(req.method, Method::GET);
            assert_eq!(req.path, "/");
            assert_eq!(req.version, "HTTP/1.0");
        }
        Err(e) => panic!("Error: {}", e),
    }

    Ok(())
}

#[test]
fn test_parse_response() -> Result<(), Box<dyn Error>> {
    better_panic::install();
    let connection_header = Connection.to_string();
    let accept_encoding = AcceptEncoding.to_string();
    let mut req = Request::default();

    req.method(Method::GET)
        .path("/gzip")
        .host("httpbin.org")
        .https()
        .header(&connection_header, "close")
        .header(&accept_encoding, "gzip; deflate");

    println!("{:#?}", req);

    let mut res = req.send().unwrap();

    assert_eq!(res.status.protocol_version, "HTTP/1.1");
    assert_eq!(res.status.status_code, StatusCode::Success);
    assert_eq!(res.status.description, "OK");
    assert_eq!(
        res.headers.get(&Connection.to_string()),
        Some(&String::from("CLOSE"))
    );
    assert_eq!(
        res.headers.get(&ContentType.to_string()),
        Some(&String::from("APPLICATION/JSON"))
    );

    match &mut res.body {
        Some(ref mut body) => match body {
            Body::Single(ref mut body) => {
                body.decompress(&res.headers)?;
            }
            Body::Multi(_) => unimplemented!(),
        },
        None => panic!("No body for response."),
    };

    dbg!(res);

    Ok(())
}
