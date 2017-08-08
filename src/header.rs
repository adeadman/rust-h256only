use std::default::Default;

#[derive(Debug, PartialEq, RustcDecodable, RustcEncodable)]
pub struct Header {
    pub typ: Option<HeaderType>,
    pub kid: Option<String>,
}


#[derive(Debug, PartialEq, RustcDecodable, RustcEncodable)]
#[allow(non_camel_case_types)]
pub enum HeaderType {
    h256only,
}

impl Default for Header {
    fn default() -> Header {
        Header {
            typ: Some(HeaderType::h256only),
            kid: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use Component;
    use header::{
        Header,
        HeaderType,
    };

    #[test]
    fn from_base64() {
        let enc = "eyJ0eXAiOiJoMjU2b25seSJ9";
        let header = Header::from_base64(enc).unwrap();

        assert_eq!(header.typ.unwrap(), HeaderType::h256only);


        let enc = "eyJraWQiOiIxS1NGM2cifQ==";
        let header = Header::from_base64(enc).unwrap();

        assert_eq!(header.kid.unwrap(), "1KSF3g".to_string());
    }

    #[test]
    fn roundtrip() {
        let header: Header = Default::default();
        let enc = Component::to_base64(&header).unwrap();
        assert_eq!(header, Header::from_base64(&*enc).unwrap());
    }
}
