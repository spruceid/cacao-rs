use super::CacaoProfile;
use serde::{Deserialize, Serialize};
use varsig::either::EitherSignature;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Either<A: CacaoProfile, B: CacaoProfile> {
    A(A::Facts),
    B(B::Facts),
}

impl<A, B> CacaoProfile for Either<A, B>
where
    A: CacaoProfile,
    B: CacaoProfile,
{
    type Signature = EitherSignature<A::Signature, B::Signature>;
    type Facts = Either<A, B>;
}
