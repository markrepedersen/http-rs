mod parse;
use nom::{
    bytes::{
        streaming::take_till,
        streaming::{tag, take_while},
    },
    character::{is_alphabetic, streaming::crlf},
    error::context,
    multi::many_till,
    sequence::{preceded, terminated},
};
use parse::{Input, ParseResult};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpStream,
    str::{from_utf8, FromStr},
};
use strum_macros::EnumString;

/**
* Unicode Hexadecimal values for some common control characters.
*/
pub enum CtrlChars {
    SP = 0x20,
    CR = 0x0D,
    LF = 0x0A,
}

//-------------- REQUEST ------------------

#[derive(Debug)]
pub struct Request<'a> {
    status: RequestStatus<'a>,
    headers: Headers<'a>,
    body: Body,
}

impl<'a> Request<'a> {
    pub fn parse(i: Input<'a>) -> Result<Self, nom::Err<parse::Error<Input<'a>>>> {
        let (_, req) = context("Request", |i| {
            let (i, status) = RequestStatus::parse(i)?;
            let (i, headers) = Headers::parse(i)?;
            let (i, body) = Body::parse(i)?;
            let res = Self {
                status,
                headers,
                body,
            };

            Ok((i, res))
        })(i)?;

        Ok(req)
    }
}

#[derive(Debug, PartialEq, EnumString, Eq)]
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
    pub fn parse(i: Input) -> ParseResult<Self> {
        context("Method", |i| {
            let (i, method) = take_while(is_alphabetic)(i)?;
            Ok((i, Method::from_str(from_utf8(method).unwrap()).unwrap()))
        })(i)
    }
}

#[derive(Debug)]
pub struct RequestStatus<'a> {
    pub method: Method,
    pub path: &'a str,
    pub version: &'a str,
}

impl<'a> RequestStatus<'a> {
    pub fn parse(i: Input<'a>) -> ParseResult<Self> {
        context("Status", |i| {
            let (i, method) = Method::parse(i)?;
            let (i, path) = preceded(tag(b" "), take_till(|c| c == CtrlChars::SP as u8))(i)?;
            let (i, version) = preceded(
                tag(b" "),
                terminated(take_till(|c| c == CtrlChars::CR as u8), crlf),
            )(i)?;

            let path = from_utf8(path).unwrap();
            let version = from_utf8(version).unwrap();

            Ok((
                i,
                Self {
                    method,
                    path,
                    version,
                },
            ))
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
            let (i, key) = terminated(take_while(is_alphabetic), tag(b": "))(i)?;
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

#[derive(Debug)]
pub enum StatusCode {
    Success = 200,
    NotFound = 404,
}

#[derive(Debug)]
pub struct Status<'a> {
    pub protocol_version: &'a str,
    pub status_code: StatusCode,
    pub description: &'a str,
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
    pub status: Status<'a>,
    pub headers: Headers<'a>,
    pub body: ResponseBody<'a>,
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
            assert_eq!(req.status.method, Method::GET);
            assert_eq!(req.status.path, "/");
            assert_eq!(req.status.version, "HTTP/1.0");
            assert_eq!(req.headers.get("Host"), Some(&"www.rust-lang.org"));
            assert_eq!(req.headers.get("Connection"), Some(&"close"))
        }
        Err(e) => panic!("Error: {}", e),
    }

    Ok(())
}

#[test]
fn test_parse_response() -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(format!("www.rust-lang.org:80"))?;
    let mut data = String::new();

    data.push_str("GET / HTTP/1.0");
    data.push_str("\r\n");
    data.push_str("Host: www.rust-lang.org");
    data.push_str("\r\n");
    data.push_str("Connection: close");
    data.push_str("\r\n");
    data.push_str("\r\n");

    println!("request_data = {:?}", data);

    stream.write_all(data.as_bytes())?;

    let mut buf: Vec<u8> = vec![];

    stream.read_to_end(&mut buf)?;

    match Request::parse(&buf) {
        Ok(req) => println!("{:#?}", req),
        Err(e) => println!("{:#?}", e),
    };

    println!("{:#?}", std::str::from_utf8(&mut buf));

    Ok(())
}
