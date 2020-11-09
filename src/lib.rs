mod parse;
use cookie_factory::multi::all;
use cookie_factory::sequence::tuple;
use cookie_factory::{combinator::string, gen, SerializeFn};
use nom::character::streaming::space1;
use nom::{
    bytes::{
        streaming::take_till,
        streaming::{tag, take_while},
    },
    character::{
        is_alphabetic,
        streaming::{crlf, digit1},
    },
    error::context,
    multi::many_till,
    sequence::{preceded, terminated},
};
use parse::{Input, ParseResult};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpStream,
    str::{from_utf8, from_utf8_unchecked, FromStr},
    string::ToString,
};
use strum_macros::{Display, EnumString};

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
    HOST,
    CONNECTION,
    ACCEPT,
}

/**
 * Serialize to binary the CRLF control character.
 */
pub fn serialize_crlf<'a, W: std::io::Write + 'a>() -> impl SerializeFn<W> + 'a {
    string("\r\n")
}

/**
 * Serialize to binary the space character.
 */
pub fn serialize_space<'a, W: std::io::Write + 'a>() -> impl SerializeFn<W> + 'a {
    string(" ")
}

//-------------- REQUEST ------------------
#[derive(Debug)]
pub struct Request<'a> {
    pub method: Method,
    pub path: &'a str,
    pub version: &'a str,
    pub headers: Headers<'a>,
    pub body: Option<Body>,
}

impl<'a> Request<'a> {
    fn serialize<W: std::io::Write + 'a>(&'a self) -> impl SerializeFn<W> + 'a {
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

    /**
     * Send the request.
     */
    pub fn send(&self) -> Result<(), Box<dyn std::error::Error>> {
        match self.headers.get(&CommonHeaders::HOST.to_string()) {
            Some(host) => {
                let mut stream = TcpStream::connect(host)?;
                let buf = Vec::new();
                let (mut buf, _) = gen(self.serialize(), buf)?;

                stream.write_all(&mut buf)?;

                let mut buf: Vec<u8> = vec![];

                stream.read_to_end(&mut buf)?;

                match Response::parse(&mut buf) {
                    Ok(res) => {
                        assert_eq!(res.status.protocol_version, "HTTP/1.1");
                        assert_eq!(res.status.status_code, StatusCode::MovedPermanently);
                        assert_eq!(res.status.description, "Moved Permanently");
                        assert_eq!(res.headers.get("Connection"), Some(&"close"));
                        assert_eq!(res.headers.get("Content-Type"), Some(&"text/html"));
                        dbg!(res);
                    }
                    Err(e) => panic!("Error: {}", e),
                };

                Ok(())
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
     * Set the URL of the request.
     */
    pub fn url(&mut self, url: &'a str) -> &mut Self {
        self.header("HOST", url);
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
    pub fn body(&mut self, body: Body) -> &mut Self {
        self.body = Some(body);
        self
    }

    /**
     * Parse a request from a stream of bytes.
     */
    pub fn parse(i: Input<'a>) -> Result<Self, nom::Err<parse::Error<Input<'a>>>> {
        let (_, req) = context("Request", |i| {
            let (i, method) = Method::parse(i)?;
            let (i, path) = preceded(space1, take_till(|c| c == CtrlChars::Space as u8))(i)?;
            let (i, version) = preceded(
                space1,
                terminated(take_till(|c| c == CtrlChars::CR as u8), crlf),
            )(i)?;
            let (i, headers) = Headers::parse(i)?;
            let (i, body) = Body::parse(i)?;
            let res = Self {
                method,
                path: from_utf8(path).unwrap(),
                version: from_utf8(version).unwrap(),
                headers,
                body: Some(body),
            };

            Ok((i, res))
        })(i)?;

        Ok(req)
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
    pub fn serialize<'a, W: std::io::Write + 'a>(&'a self) -> impl SerializeFn<W> + 'a {
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
pub struct Header<'a> {
    pub key: &'a str,
    pub value: &'a str,
}

impl<'a> Header<'a> {
    pub fn parse(i: Input<'a>) -> ParseResult<Self> {
        context("Header", |i| {
            let (i, key) = terminated(take_till(|c| c == CtrlChars::Colon as u8), tag(b": "))(i)?;
            let (i, value) = terminated(take_till(|c| c == CtrlChars::CR as u8), crlf)(i)?;
            let res = Self {
                key: from_utf8(key).unwrap(),
                value: from_utf8(value).unwrap(),
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(Debug)]
pub struct Headers<'a> {
    headers: HashMap<&'a str, &'a str>,
}

impl<'a> Headers<'a> {
    pub fn serialize<W: std::io::Write + 'a>(&'a self) -> impl SerializeFn<W> + 'a {
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

    pub fn parse(i: Input<'a>) -> ParseResult<Self> {
        context("Headers", |i| {
            let (i, (data, _)) = many_till(Header::parse, crlf)(i)?;
            let mut headers = HashMap::new();

            for header in data {
                headers.insert(header.key, header.value);
            }

            Ok((i, Self { headers }))
        })(i)
    }

    pub fn insert(&mut self, key: &'a str, val: &'a str) {
        self.headers.insert(key, val);
    }

    pub fn get(&self, key: &str) -> Option<&&'a str> {
        self.headers.get(key)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.headers.contains_key(key)
    }
}

#[derive(Debug)]
pub enum Body {
    Single(SinglePartBody),
    Multi(MultiPartBody),
}

impl Body {
    pub fn parse(i: Input) -> ParseResult<Self> {
        context("Body", |i| {
            let (i, body) = SinglePartBody::parse(i)?;
            Ok((i, Body::Single(body)))
        })(i)
    }
}

#[derive(Debug)]
pub struct SinglePartBody {
    data: Vec<u8>,
}

impl SinglePartBody {
    pub fn parse(i: Input) -> ParseResult<Self> {
        context("Single-part Body", |i| {
            let data = vec![];

            Ok((i, Self { data }))
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
    NotFound = 404,
    MovedPermanently = 301,
}

impl StatusCode {
    pub fn from_str(i: Input) -> Option<Self> {
        use StatusCode::*;

        unsafe {
            match from_utf8_unchecked(i) {
                "200" => Some(Success),
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
                            "[UTF-8 decoding] Invalid HTTP status code '{}'",
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
pub struct ResponseStatus<'a> {
    pub protocol_version: &'a str,
    pub status_code: StatusCode,
    pub description: &'a str,
}

impl<'a> ResponseStatus<'a> {
    pub fn parse(i: Input<'a>) -> ParseResult<Self> {
        context("Status", |i| {
            let (i, protocol_version) =
                terminated(take_till(|c| c == CtrlChars::Space as u8), space1)(i)?;
            let (i, status_code) = StatusCode::parse(i)?;
            let (i, description) = terminated(take_till(|c| c == CtrlChars::CR as u8), crlf)(i)?;
            let res = Self {
                protocol_version: from_utf8(protocol_version).unwrap(),
                status_code,
                description: from_utf8(description).unwrap(),
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(Debug)]
pub struct SingleResourceResponseBody<'a> {
    pub file: &'a str,
}

#[derive(Debug)]
pub struct ChunkedResponseBody<'a> {
    pub file: &'a str,
}

#[derive(Debug)]
pub struct MultiResourceResponseBody<'a> {
    pub files: Vec<SingleResourceResponseBody<'a>>,
}

#[derive(Debug)]
pub enum ResponseBody<'a> {
    Single(SingleResourceResponseBody<'a>),
    ChunkedSingle(ChunkedResponseBody<'a>),
    Multi(MultiResourceResponseBody<'a>),
}

#[derive(Debug)]
pub struct Response<'a> {
    pub status: ResponseStatus<'a>,
    pub headers: Headers<'a>,
    pub body: Body,
}

impl<'a> Response<'a> {
    pub fn parse(i: Input<'a>) -> Result<Self, nom::Err<parse::Error<Input<'a>>>> {
        let (_, response) = context("Response", |i| {
            let (i, status) = ResponseStatus::parse(i)?;
            let (i, headers) = Headers::parse(i)?;
            let (i, body) = Body::parse(i)?;
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
fn test_parse_request() -> Result<(), Box<dyn std::error::Error>> {
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
            assert_eq!(
                req.headers.get(&CommonHeaders::HOST.to_string()),
                Some(&"www.rust-lang.org")
            );
            assert_eq!(
                req.headers.get(&CommonHeaders::CONNECTION.to_string()),
                Some(&"close")
            )
        }
        Err(e) => panic!("Error: {}", e),
    }

    Ok(())
}

#[test]
fn test_parse_response() -> Result<(), Box<dyn std::error::Error>> {
    Request::default()
        .method(Method::GET)
        .path("/")
        .url("www.rust-lang.org:80")
        .header(&CommonHeaders::CONNECTION.to_string(), "close")
        .send()?;

    Ok(())
}
