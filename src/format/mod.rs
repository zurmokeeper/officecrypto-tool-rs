pub mod xls97;
pub mod doc97;
pub mod ppt97;

// Re-export with module prefix to avoid naming conflicts
pub use xls97::decrypt_workbook;
pub use xls97::is_encrypted as is_xls_encrypted;
pub use doc97::is_encrypted as is_doc_encrypted;
pub use ppt97::is_encrypted as is_ppt_encrypted;
