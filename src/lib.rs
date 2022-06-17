use std::fmt::Debug;

use async_trait::async_trait;
use libipld::{cbor::DagCbor, DagCbor, Ipld};
pub use siwe;

pub mod siwe_cacao;

#[derive(DagCbor, Debug)]
pub struct CACAO<S, T>
where
    S: SignatureScheme<T>,
    S::Signature: DagCbor,
    T: Representation,
{
    h: T::Header,
    p: T::Payload,
    s: S::Signature,
}

impl<S, R> CACAO<S, R>
where
    S: SignatureScheme<R>,
    S::Signature: DagCbor,
    R: Representation,
{
    pub fn new(p: R::Payload, s: S::Signature, h: Option<R::Header>) -> Self {
        Self {
            h: h.unwrap_or_else(R::header),
            p,
            s,
        }
    }

    pub fn header(&self) -> &R::Header {
        &self.h
    }

    pub fn payload(&self) -> &R::Payload {
        &self.p
    }

    pub fn signature(&self) -> &S::Signature {
        &self.s
    }

    pub async fn verify(&self) -> Result<(), S::Err>
    where
        S: Send + Sync,
        S::Signature: Send + Sync,
        R::Payload: Send + Sync + Debug,
        R::Header: Send + Sync + Debug,
    {
        S::verify_cacao(self).await
    }
}

pub trait Representation {
    type Payload: DagCbor;
    type Header: DagCbor;
    fn header() -> Self::Header;
}

#[async_trait]
pub trait SignatureScheme<T>: Debug
where
    T: Representation,
{
    type Signature: Debug;
    type Err;
    async fn verify(payload: &T::Payload, sig: &Self::Signature) -> Result<(), Self::Err>
    where
        Self::Signature: Send + Sync;

    async fn verify_cacao(cacao: &CACAO<Self, T>) -> Result<(), Self::Err>
    where
        Self: Sized,
        Self::Signature: Send + Sync + Debug + DagCbor,
        T::Payload: Send + Sync + Debug,
        T::Header: Send + Sync + Debug,
    {
        Self::verify(cacao.payload(), cacao.signature()).await
    }
}

#[derive(DagCbor)]
pub struct CACAOIpld<P, H>
where
    H: DagCbor,
    P: DagCbor,
{
    #[ipld(rename = "h")]
    header: H,
    #[ipld(rename = "p")]
    payload: P,
    #[ipld(rename = "s")]
    signature: Ipld,
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use libipld::{cbor::DagCborCodec, codec::Decode};
    use siwe_cacao::{Header, Payload};
    use std::io::Cursor;
    #[test]
    fn test_ipld() {
        let _cacao = CACAOIpld::<Payload, Header>::decode(
            DagCborCodec,
            &mut Cursor::new([
                163u8, 97u8, 104u8, 161u8, 97u8, 116u8, 103u8, 101u8, 105u8, 112u8, 52u8, 51u8,
                54u8, 49u8, 97u8, 112u8, 168u8, 99u8, 97u8, 117u8, 100u8, 120u8, 56u8, 100u8,
                105u8, 100u8, 58u8, 107u8, 101u8, 121u8, 58u8, 122u8, 54u8, 77u8, 107u8, 114u8,
                66u8, 100u8, 78u8, 100u8, 119u8, 85u8, 80u8, 110u8, 88u8, 68u8, 86u8, 68u8, 49u8,
                68u8, 67u8, 120u8, 101u8, 100u8, 122u8, 86u8, 86u8, 66u8, 112u8, 97u8, 71u8, 105u8,
                56u8, 97u8, 83u8, 109u8, 111u8, 88u8, 70u8, 65u8, 101u8, 75u8, 78u8, 103u8, 116u8,
                65u8, 101u8, 114u8, 56u8, 99u8, 105u8, 97u8, 116u8, 120u8, 24u8, 50u8, 48u8, 50u8,
                49u8, 45u8, 48u8, 57u8, 45u8, 51u8, 48u8, 84u8, 49u8, 54u8, 58u8, 50u8, 53u8, 58u8,
                50u8, 52u8, 46u8, 48u8, 48u8, 48u8, 90u8, 99u8, 105u8, 115u8, 115u8, 120u8, 59u8,
                100u8, 105u8, 100u8, 58u8, 112u8, 107u8, 104u8, 58u8, 101u8, 105u8, 112u8, 49u8,
                53u8, 53u8, 58u8, 49u8, 58u8, 48u8, 120u8, 66u8, 100u8, 57u8, 68u8, 57u8, 99u8,
                55u8, 68u8, 67u8, 51u8, 56u8, 57u8, 55u8, 49u8, 53u8, 97u8, 56u8, 57u8, 102u8,
                67u8, 56u8, 49u8, 52u8, 57u8, 69u8, 52u8, 97u8, 53u8, 66u8, 101u8, 57u8, 49u8,
                51u8, 51u8, 54u8, 66u8, 50u8, 55u8, 57u8, 54u8, 101u8, 110u8, 111u8, 110u8, 99u8,
                101u8, 104u8, 51u8, 50u8, 56u8, 57u8, 49u8, 55u8, 53u8, 55u8, 102u8, 100u8, 111u8,
                109u8, 97u8, 105u8, 110u8, 107u8, 115u8, 101u8, 114u8, 118u8, 105u8, 99u8, 101u8,
                46u8, 111u8, 114u8, 103u8, 103u8, 118u8, 101u8, 114u8, 115u8, 105u8, 111u8, 110u8,
                97u8, 49u8, 105u8, 114u8, 101u8, 115u8, 111u8, 117u8, 114u8, 99u8, 101u8, 115u8,
                130u8, 120u8, 53u8, 105u8, 112u8, 102u8, 115u8, 58u8, 47u8, 47u8, 81u8, 109u8,
                101u8, 55u8, 115u8, 115u8, 51u8, 65u8, 82u8, 86u8, 103u8, 120u8, 118u8, 54u8,
                114u8, 88u8, 113u8, 86u8, 80u8, 105u8, 105u8, 107u8, 77u8, 74u8, 56u8, 117u8, 50u8,
                78u8, 76u8, 103u8, 109u8, 103u8, 115u8, 122u8, 103u8, 49u8, 51u8, 112u8, 89u8,
                114u8, 68u8, 75u8, 69u8, 111u8, 105u8, 117u8, 120u8, 38u8, 104u8, 116u8, 116u8,
                112u8, 115u8, 58u8, 47u8, 47u8, 101u8, 120u8, 97u8, 109u8, 112u8, 108u8, 101u8,
                46u8, 99u8, 111u8, 109u8, 47u8, 109u8, 121u8, 45u8, 119u8, 101u8, 98u8, 50u8, 45u8,
                99u8, 108u8, 97u8, 105u8, 109u8, 46u8, 106u8, 115u8, 111u8, 110u8, 105u8, 115u8,
                116u8, 97u8, 116u8, 101u8, 109u8, 101u8, 110u8, 116u8, 120u8, 65u8, 73u8, 32u8,
                97u8, 99u8, 99u8, 101u8, 112u8, 116u8, 32u8, 116u8, 104u8, 101u8, 32u8, 83u8,
                101u8, 114u8, 118u8, 105u8, 99u8, 101u8, 79u8, 114u8, 103u8, 32u8, 84u8, 101u8,
                114u8, 109u8, 115u8, 32u8, 111u8, 102u8, 32u8, 83u8, 101u8, 114u8, 118u8, 105u8,
                99u8, 101u8, 58u8, 32u8, 104u8, 116u8, 116u8, 112u8, 115u8, 58u8, 47u8, 47u8,
                115u8, 101u8, 114u8, 118u8, 105u8, 99u8, 101u8, 46u8, 111u8, 114u8, 103u8, 47u8,
                116u8, 111u8, 115u8, 97u8, 115u8, 162u8, 97u8, 115u8, 120u8, 132u8, 48u8, 120u8,
                49u8, 48u8, 57u8, 51u8, 49u8, 51u8, 101u8, 55u8, 53u8, 50u8, 53u8, 100u8, 101u8,
                97u8, 53u8, 53u8, 101u8, 99u8, 57u8, 97u8, 51u8, 99u8, 99u8, 98u8, 98u8, 54u8,
                51u8, 101u8, 97u8, 56u8, 100u8, 54u8, 56u8, 52u8, 48u8, 54u8, 51u8, 54u8, 54u8,
                50u8, 53u8, 48u8, 99u8, 102u8, 48u8, 56u8, 56u8, 48u8, 100u8, 54u8, 55u8, 48u8,
                51u8, 50u8, 98u8, 52u8, 53u8, 55u8, 97u8, 98u8, 51u8, 51u8, 99u8, 57u8, 50u8, 54u8,
                99u8, 54u8, 55u8, 102u8, 102u8, 51u8, 102u8, 99u8, 99u8, 54u8, 54u8, 97u8, 99u8,
                51u8, 49u8, 98u8, 97u8, 97u8, 54u8, 56u8, 54u8, 56u8, 97u8, 56u8, 48u8, 97u8, 49u8,
                50u8, 102u8, 98u8, 101u8, 54u8, 98u8, 55u8, 54u8, 51u8, 56u8, 97u8, 56u8, 57u8,
                102u8, 52u8, 102u8, 54u8, 100u8, 53u8, 49u8, 97u8, 48u8, 50u8, 50u8, 57u8, 53u8,
                57u8, 48u8, 99u8, 102u8, 54u8, 54u8, 55u8, 54u8, 102u8, 49u8, 99u8, 97u8, 116u8,
                102u8, 101u8, 105u8, 112u8, 49u8, 57u8, 49u8,
            ]),
        )
        .unwrap();
    }
}
