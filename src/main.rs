mod parse;

use clap::Clap;
use nom::{
    bytes::{
        streaming::take,
        streaming::{tag, take_while},
    },
    character::is_alphanumeric,
    multi::many_till,
    sequence::delimited,
};
use parse::{Input, ParseResult};
use std::str::from_utf8;
use std::str::FromStr;
use strum_macros::EnumString;

#[derive(Clap)]
#[clap(version = "1.0", author = "Mark Pedersen")]
pub struct CLI {
    #[clap(short, long, about = "The URL of the request.")]
    pub url: String,
}

/**
* Consumes two bytes, which equals a CRLF.
**/
pub fn take_crlf(i: Input) -> ParseResult<Input> {
    take(2usize)(i)
}

//-------------- REQUEST ------------------

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
        let (i, method) = delimited(take_crlf, take_while(is_alphanumeric), tag(b" "))(i)?;

        Ok((i, Method::from_str(from_utf8(method).unwrap()).unwrap()))
    }
}

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

pub struct Header<'a> {
    key: &'a str,
    value: &'a str,
}

impl<'a> Header<'a> {
    pub fn parse(i: Input<'a>) -> ParseResult<Self> {
        let (i, key) = delimited(take_crlf, take_while(is_alphanumeric), tag(b":"))(i)?;
        let (i, value) = take_while(is_alphanumeric)(i)?;
        let res = Self {
            key: from_utf8(key).unwrap(),
            value: from_utf8(value).unwrap(),
        };

        Ok((i, res))
    }
}

pub struct Headers<'a> {
    headers: Vec<Header<'a>>,
}

impl<'a> Headers<'a> {
    pub fn parse(i: Input<'a>) -> ParseResult<Self> {
        let (i, (headers, _)) = many_till(Header::parse, tag(b"\r\n"))(i)?;

        Ok((i, Self { headers }))
    }
}

pub enum Body<'a> {
    Single(SinglePartBody<'a>),
    Multi(MultiPartBody<'a>),
}

pub struct SinglePartBody<'a> {
    data: &'a str,
}

pub struct MultiPartBody<'a> {
    data: Vec<&'a str>,
}

pub struct Request<'a> {
    status: RequestStatus<'a>,
    body: Body<'a>,
}

// -------------------- RESPONSE---------------------

pub enum StatusCode {
    Success = 200,
    NotFound = 404,
}

pub struct Status<'a> {
    pub protocol_version: &'a str,
    pub status_code: StatusCode,
    pub description: &'a str,
}

pub struct SingleResourceResponseBody<'a> {
    pub file: &'a str,
}

pub struct ChunkedResponseBody<'a> {
    pub file: &'a str,
}

pub struct MultiResourceResponseBody<'a> {
    pub files: Vec<SingleResourceResponseBody<'a>>,
}

pub enum ResponseBody<'a> {
    Single(SingleResourceResponseBody<'a>),
    ChunkedSingle(ChunkedResponseBody<'a>),
    Multi(MultiResourceResponseBody<'a>),
}

pub struct Response<'a> {
    pub status: Status<'a>,
    pub headers: Headers<'a>,
    pub body: ResponseBody<'a>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli: CLI = CLI::parse();

    Ok(())
}
