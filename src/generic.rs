use super::{Payload, SignatureScheme, VerificationError};
use async_trait::async_trait;
use std::marker::PhantomData;

#[derive(Default)]
pub struct GenericScheme<R, S>(PhantomData<R>, PhantomData<S>);

#[async_trait]
impl<R, S, P> SignatureScheme for GenericScheme<R, S>
where
    R: Representation<Output = P>,
    S: SignatureType,
    S::Payload: Send + Sync,
    S::VerificationMaterial: Send + Sync,
    R::Err: Send + Sync,
    P: Into<S::Payload> + Send,
{
    type Signature = S::Signature;
    fn id() -> String {
        [R::ID, "-", S::ID].concat()
    }

    async fn verify(payload: &Payload, sig: &Self::Signature) -> Result<(), VerificationError>
    where
        Self::Signature: Send + Sync,
    {
        if !payload.valid_now() {
            return Err(VerificationError::NotCurrentlyValid);
        };
        S::verify(
            &R::serialize(&payload)
                .map_err(|_| VerificationError::Serialization)?
                .into(),
            &S::get_vmat(&payload).ok_or(VerificationError::MissingVerificationMaterial)?,
            &sig,
        )
        .await
        .map_err(|_| VerificationError::Crypto)?;
        Ok(())
    }
}

pub trait Representation {
    const ID: &'static str;
    type Err;
    type Output;
    fn serialize(payload: &Payload) -> Result<Self::Output, Self::Err>;
}

pub trait Parse: Representation {
    type ParseErr;
    fn deserialize(rep: &Self::Output) -> Result<Payload, Self::ParseErr>;
}

#[async_trait]
pub trait SignatureType {
    const ID: &'static str;
    type Signature;
    type Payload;
    type VerificationMaterial;
    type Output;
    type Err;
    async fn verify(
        payload: &Self::Payload,
        key: &Self::VerificationMaterial,
        signature: &Self::Signature,
    ) -> Result<Self::Output, Self::Err>;
    fn get_vmat(payload: &Payload) -> Option<Self::VerificationMaterial>;
}
