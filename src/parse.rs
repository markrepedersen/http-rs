use nom::{
    error::{ErrorKind as NomErrorKind, ParseError as NomParseError},
    ErrorConvert, Slice,
};
use std::{
    fmt::{self, Debug},
    ops::RangeFrom,
};

pub type Input<'a> = &'a [u8];
pub type ParseResult<'a, T> = nom::IResult<Input<'a>, T, Error<Input<'a>>>;

impl<I> ErrorConvert<Error<I>> for Error<(I, usize)>
where
    I: Slice<RangeFrom<usize>>,
{
    fn convert(self) -> Error<I> {
        let errors = self
            .errors
            .into_iter()
            .map(|((rest, offset), err)| (rest.slice(offset / 8..), err))
            .collect();
        Error { errors }
    }
}

#[derive(Debug)]
pub enum ErrorKind {
    Nom(NomErrorKind),
    Context(&'static str),
    Custom(String),
    Malformed,
}

pub struct Error<I> {
    pub errors: Vec<(I, ErrorKind)>,
}

impl<I> Error<I> {
    pub fn malformed(input: I) -> Self {
        Self {
            errors: vec![(input, ErrorKind::Malformed)],
        }
    }

    pub fn custom(input: I, msg: String) -> Self {
        Self {
            errors: vec![(input, ErrorKind::Custom(msg))],
        }
    }
}

impl<'a> fmt::Debug for Error<&'a [u8]> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "/!\\ Parsing error\n")?;

        let mut shown_input = None;
        let margin_left = 4;
        let margin_str = " ".repeat(margin_left);
        let maxlen = 60;
        let print_slice =
            |f: &mut fmt::Formatter, s: &[u8], offset: usize, len: usize| -> fmt::Result {
                let (s, offset, len) = {
                    let avail_after = s.len() - offset;
                    let after = std::cmp::min(avail_after, maxlen / 2);

                    let avail_before = offset;
                    let before = std::cmp::min(avail_before, maxlen / 2);

                    let new_start = offset - before;
                    let new_end = offset + after;
                    let new_offset = before;
                    let new_len = std::cmp::min(new_end - new_start, len);

                    (&s[new_start..new_end], new_offset, new_len)
                };

                write!(f, "{}", margin_str)?;
                for b in s {
                    write!(f, "{:02X} ", b)?;
                }
                write!(f, "\n")?;

                write!(f, "{}", margin_str)?;
                for i in 0..s.len() {
                    if i == offset + len - 1 {
                        write!(f, "~~")?;
                    } else if (offset..offset + len).contains(&i) {
                        write!(f, "~~~")?;
                    } else {
                        write!(f, "   ")?;
                    };
                }
                write!(f, "\n")?;

                Ok(())
            };

        for (input, kind) in self.errors.iter().rev() {
            let prefix = match kind {
                ErrorKind::Context(ctx) => format!("...in {}", ctx),
                ErrorKind::Nom(err) => format!("nom error {:?}", err),
                ErrorKind::Custom(err) => format!("err: {}", err),
                ErrorKind::Malformed => format!("Malformed packet"),
            };

            write!(f, "{}\n", prefix)?;
            match shown_input {
                None => {
                    shown_input.replace(input);
                    print_slice(f, input, 0, input.len())?;
                }
                Some(parent_input) => {
                    use nom::Offset;
                    let offset = parent_input.offset(input);
                    print_slice(f, parent_input, offset, input.len())?;
                }
            };
        }
        Ok(())
    }
}

impl<I> NomParseError<I> for Error<I> {
    fn from_error_kind(input: I, kind: NomErrorKind) -> Self {
        let errors = vec![(input, ErrorKind::Nom(kind))];
        Self { errors }
    }

    fn append(input: I, kind: NomErrorKind, mut other: Self) -> Self {
        other.errors.push((input, ErrorKind::Nom(kind)));
        other
    }

    fn add_context(input: I, ctx: &'static str, mut other: Self) -> Self {
        other.errors.push((input, ErrorKind::Context(ctx)));
        other
    }
}
