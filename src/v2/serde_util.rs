use multidid::MultiDid;
use serde::Deserialize;
use serde_with::{DeserializeAs, SerializeAs};
use varsig::{VarSig, VarSigTrait};

pub struct MultiDidAsBytes;

impl SerializeAs<MultiDid> for MultiDidAsBytes {
    fn serialize_as<S>(source: &MultiDid, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&source.to_vec())
    }
}

impl<'de> DeserializeAs<'de, MultiDid> for MultiDidAsBytes {
    fn deserialize_as<D>(deserializer: D) -> Result<MultiDid, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = Vec::<u8>::deserialize(deserializer)?;
        let mut b: &[u8] = v.as_ref();
        MultiDid::from_reader(&mut b).map_err(serde::de::Error::custom)
    }
}

pub struct VarSigAsBytes;

impl<V> SerializeAs<VarSig<V>> for VarSigAsBytes
where
    V: VarSigTrait,
{
    fn serialize_as<S>(source: &VarSig<V>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&source.to_vec().map_err(serde::ser::Error::custom)?)
    }
}

impl<'de, V> DeserializeAs<'de, VarSig<V>> for VarSigAsBytes
where
    V: VarSigTrait,
{
    fn deserialize_as<D>(deserializer: D) -> Result<VarSig<V>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = Vec::<u8>::deserialize(deserializer)?;
        let mut b: &[u8] = v.as_ref();
        VarSig::from_reader(&mut b).map_err(serde::de::Error::custom)
    }
}
