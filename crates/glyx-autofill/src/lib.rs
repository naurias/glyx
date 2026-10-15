use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Candidate {
    pub id: Uuid,
    pub name: String,
    pub item_type: String,
}

pub trait AutofillProvider {
    type Error: std::error::Error;
    fn candidates(&self, query: &str) -> Result<Vec<Candidate>, Self::Error>;
    fn fill(&self, id: &Uuid) -> Result<(), Self::Error>;
}
