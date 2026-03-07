use thiserror::Error;

#[derive(Debug, Error)]
pub enum AlgoError {
    #[error("codec error: {context}")]
    Codec {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        context: String,
    },

    #[error("REST client error: {context}")]
    RestClient {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        context: String,
    },

    #[error("conformance error: {message}")]
    Conformance { message: String },

    #[error("not found: {0}")]
    NotFound(String),

    #[error("I/O error")]
    Io(#[from] std::io::Error),

    #[error("config error: {0}")]
    Config(String),

    #[error("validation error: {message}")]
    Validation { message: String },

    #[error("ledger error: {message}")]
    Ledger { message: String },

    #[error("AVM: {message}")]
    Avm { message: String },
}

pub type Result<T> = std::result::Result<T, AlgoError>;
