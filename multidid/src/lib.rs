use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MultiDID(String);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
