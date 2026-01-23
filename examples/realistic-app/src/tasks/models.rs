//! Task Data Models
//!
//! Defines task structures with validation.

use barbican::prelude::*;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Task entity
#[derive(Debug, Clone, Serialize)]
pub struct Task {
    pub id: String,
    pub user_id: String,
    pub title: String,
    pub description: Option<String>,
    /// Notes are encrypted at rest (SC-28)
    /// Stored as EncryptedField, decrypted for response
    pub notes: Option<String>,
    pub completed: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new task
#[derive(Debug, Deserialize)]
pub struct CreateTaskRequest {
    pub title: String,
    pub description: Option<String>,
    /// Sensitive notes - will be encrypted (SC-28)
    pub notes: Option<String>,
}

impl Validate for CreateTaskRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_length(&self.title, 1, 200, "title")?;
        if let Some(ref desc) = self.description {
            validate_length(desc, 0, 2000, "description")?;
        }
        if let Some(ref notes) = self.notes {
            validate_length(notes, 0, 10000, "notes")?;
        }
        Ok(())
    }
}

/// Request to update a task
#[derive(Debug, Deserialize)]
pub struct UpdateTaskRequest {
    pub title: Option<String>,
    pub description: Option<String>,
    pub notes: Option<String>,
    pub completed: Option<bool>,
}

impl Validate for UpdateTaskRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        if let Some(ref title) = self.title {
            validate_length(title, 1, 200, "title")?;
        }
        if let Some(ref desc) = self.description {
            validate_length(desc, 0, 2000, "description")?;
        }
        if let Some(ref notes) = self.notes {
            validate_length(notes, 0, 10000, "notes")?;
        }
        Ok(())
    }
}

/// Response for task lists
#[derive(Serialize)]
pub struct TaskListResponse {
    pub tasks: Vec<Task>,
    pub total: usize,
}
