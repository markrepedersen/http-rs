mod parse;

use clap::Clap;
use nom::{
    bytes::{
        streaming::take,
        streaming::{tag, take_while},
    },
    character::{is_alphanumeric, streaming::crlf},
    multi::many_till,
    sequence::delimited,
};
use parse::{Input, ParseResult};
use std::{
    io::Read,
    net::TcpStream,
    str::{from_utf8, FromStr},
};
use strum_macros::EnumString;

#[derive(Clap)]
#[clap(version = "1.0", author = "Mark Pedersen")]
pub struct CLI {
    #[clap(short, long, about = "The URL of the request.")]
    pub url: String,

    #[clap(
        short,
        long,
        default_value = "80",
        about = "The port to use. Uses :80 by default."
    )]
    pub port: String,
}

//-------------- REQUEST ------------------

#[derive(Debug)]
pub struct Request<'a> {
    status: RequestStatus<'a>,
    headers: Headers<'a>,
    body: Body,
}

impl<'a> Request<'a> {
    pub fn parse(i: Input<'a>) -> ParseResult<Self> {
        let (i, status) = RequestStatus::parse(i)?;
        let (i, headers) = Headers::parse(i)?;
        let (i, body) = Body::parse(i)?;
        let res = Self {
            status,
            headers,
            body,
        };

        Ok((i, res))
    }
}

#[derive(Debug, PartialEq, EnumString)]
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
        let (i, method) = delimited(crlf, take_while(is_alphanumeric), tag(b" "))(i)?;

        Ok((i, Method::from_str(from_utf8(method).unwrap()).unwrap()))
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
        let (i, method) = Method::parse(i)?;
        let (i, path) = take(2usize)(i)?;
        let (i, version) = take(2usize)(i)?;

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
    }
}

#[derive(Debug)]
pub struct Header<'a> {
    key: &'a str,
    value: &'a str,
}

impl<'a> Header<'a> {
    pub fn parse(i: Input<'a>) -> ParseResult<Self> {
        let (i, key) = delimited(crlf, take_while(is_alphanumeric), tag(b":"))(i)?;
        let (i, value) = take_while(is_alphanumeric)(i)?;
        let res = Self {
            key: from_utf8(key).unwrap(),
            value: from_utf8(value).unwrap(),
        };

        Ok((i, res))
    }
}

#[derive(Debug)]
pub struct Headers<'a> {
    headers: Vec<Header<'a>>,
}

impl<'a> Headers<'a> {
    pub fn parse(i: Input<'a>) -> ParseResult<Self> {
        let (i, (headers, _)) = many_till(Header::parse, tag(b"\r\n"))(i)?;

        Ok((i, Self { headers }))
    }
}

#[derive(Debug)]
pub enum Body {
    Single(SinglePartBody),
    Multi(MultiPartBody),
}

impl Body {
    pub fn parse(i: Input) -> ParseResult<Self> {
        let (i, body) = SinglePartBody::parse(i)?;
        Ok((i, Body::Single(body)))
    }
}

#[derive(Debug)]
pub struct SinglePartBody {
    data: Vec<u8>,
}

impl SinglePartBody {
    pub fn parse(i: Input) -> ParseResult<Self> {
        let data = vec![];

        Ok((i, Self { data }))
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli: CLI = CLI::parse();
    let mut stream = TcpStream::connect(cli.url + &cli.port)?;
    let mut buf: Vec<u8> = vec![];

    stream.read_to_end(&mut buf)?;

    if let Ok(req) = Request::parse(&buf) {
        dbg!(req);
    }

    Ok(())
}
