extern crate crypto;
extern crate rustc_serialize;

use rustc_serialize::{
    json,
    Decodable,
    Encodable,
};
use rustc_serialize::base64::{
    self,
    CharacterSet,
    FromBase64,
    Newline,
    ToBase64,
};
pub use error::Error;
pub use header::Header;
pub use claims::Claims;
pub use claims::Registered;

pub mod error;
pub mod header;
pub mod claims;
mod crypt;

#[derive(Debug, Default)]
pub struct Token<H, C>
    where H: Component, C: Component {
    raw: Option<String>,
    pub header: H,
    pub claims: C,
}

pub trait Component: Sized {
    fn from_base64(raw: &str) -> Result<Self, Error>;
    fn to_base64(&self) -> Result<String, Error>;
}

impl<T> Component for T
    where T: Encodable + Decodable + Sized {

    /// Parse from a string.
    fn from_base64(raw: &str) -> Result<T, Error> {
        let data = try!(raw.from_base64());
        let s = try!(String::from_utf8(data));
        Ok(try!(json::decode(&*s)))
    }

    /// Encode to a string.
    fn to_base64(&self) -> Result<String, Error> {
        let s = try!(json::encode(&self));
        let enc = (&*s).as_bytes().to_base64(BASE_CONFIG);
        Ok(enc)
    }
}

impl<H, C> Token<H, C>
    where H: Component, C: Component {
    pub fn new(header: H, claims: C) -> Token<H, C> {
        Token {
            raw: None,
            header: header,
            claims: claims,
        }
    }

    /// Parse a token from a string.
    pub fn parse(raw: &str) -> Result<Token<H, C>, Error> {
        let pieces: Vec<_> = raw.split('.').collect();

        Ok(Token {
            raw: Some(raw.into()),
            header: try!(Component::from_base64(pieces[0])),
            claims: try!(Component::from_base64(pieces[1])),
        })
    }

    /// Verify a from_base64d token with a key
    pub fn verify(&self, key: &[u8]) -> bool {
        let raw = match self.raw {
            Some(ref s) => s,
            None => return false,
        };

        let pieces: Vec<_> = raw.rsplitn(2, '.').collect();
        let sig = pieces[0];
        let data = pieces[1];

        crypt::verify(sig, data, key)
    }

    /// Generate the signed token from a key
    pub fn signed(&self, key: &[u8]) -> Result<String, Error> {
        let header = try!(Component::to_base64(&self.header));
        let claims = try!(self.claims.to_base64());
        let data = format!("{}.{}", header, claims);

        let sig = crypt::sign(&*data, key);
        Ok(format!("{}.{}", data, sig))
    }
}

impl<H, C> PartialEq for Token<H, C>
    where H: Component + PartialEq, C: Component + PartialEq{
    fn eq(&self, other: &Token<H, C>) -> bool {
        self.header == other.header &&
        self.claims == other.claims
    }
}

const BASE_CONFIG: base64::Config = base64::Config {
    char_set: CharacterSet::UrlSafe,
    newline: Newline::LF,
    pad: false,
    line_length: None,
};

#[cfg(test)]
mod tests {
    use crypt::{
        sign,
        verify,
    };
    use Claims;
    use Token;
    use header::{Header, HeaderType};

    #[test]
    pub fn sign_data() {
        let header = "eyJ0eXAiOiJoMjU2b25seSIsImFsZyI6IkhTMjU2In0";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
        let real_sig = "33Ube1fa0tUFM8T1IrRT_7Tts1j4EBMKKW7mlC9c6KE";
        let data = format!("{}.{}", header, claims);

        let sig = sign(&*data, "secret".as_bytes());

        assert_eq!(sig, real_sig);
    }

    #[test]
    pub fn verify_data() {
        let header = "eyJ0eXAiOiJoMjU2b25seSIsImFsZyI6IkhTMjU2In0";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
        let target = "33Ube1fa0tUFM8T1IrRT_7Tts1j4EBMKKW7mlC9c6KE";
        let data = format!("{}.{}", header, claims);

        assert!(verify(target, &*data, "secret".as_bytes()));
    }

    #[test]
    pub fn raw_data() {
        let raw = "eyJ0eXAiOiJoMjU2b25seSIsImFsZyI6IkhTMjU2In0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.33Ube1fa0tUFM8T1IrRT_7Tts1j4EBMKKW7mlC9c6KE";
        let token = Token::<Header, Claims>::parse(raw).unwrap();

        {
            assert_eq!(token.header.typ, Some(HeaderType::h256only));
        }
        assert!(token.verify("secret".as_bytes()));
    }

    #[test]
    pub fn roundtrip() {
        let token: Token<Header, Claims> = Default::default();
        let key = "secret".as_bytes();
        let raw = token.signed(key).unwrap();
        let same = Token::parse(&*raw).unwrap();

        assert_eq!(token, same);
        assert!(same.verify(key));
    }
}
