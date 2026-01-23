//! Authentication Module
//!
//! Handles user registration, login, and session management.
//!
//! Security Controls:
//! - AC-7:  Login attempt limiting
//! - IA-2:  User identification
//! - IA-5:  Password management

pub mod handlers;
pub mod jwt;
pub mod middleware;

pub use jwt::Claims;
