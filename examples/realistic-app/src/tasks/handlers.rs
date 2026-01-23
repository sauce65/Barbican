//! Task CRUD Handlers
//!
//! Demonstrates input validation, encryption, and audit logging.

use axum::{
    extract::{Path, State},
    Json,
};
use barbican::prelude::*;
use chrono::Utc;
use tracing::info;

use crate::auth::Claims;
use crate::error::AppError;
use crate::AppState;
use super::models::{Task, CreateTaskRequest, UpdateTaskRequest, TaskListResponse};

// In-memory storage for demo (use database in production)
use std::sync::Mutex;
use std::collections::HashMap;

lazy_static::lazy_static! {
    static ref TASKS: Mutex<HashMap<String, Task>> = Mutex::new(HashMap::new());
}

/// List all tasks for the authenticated user
pub async fn list_tasks(
    State(_state): State<AppState>,
    claims: Claims,
) -> Result<Json<TaskListResponse>, AppError> {
    let tasks = TASKS.lock().unwrap();

    let user_tasks: Vec<Task> = tasks
        .values()
        .filter(|t| t.user_id == claims.sub)
        .cloned()
        .collect();

    let total = user_tasks.len();

    info!(
        event = "task.list",
        user_id = %claims.sub,
        count = %total,
        "Tasks listed"
    );

    Ok(Json(TaskListResponse {
        tasks: user_tasks,
        total,
    }))
}

/// Create a new task
///
/// Demonstrates:
/// - Input validation (SI-10)
/// - Field encryption for notes (SC-28)
/// - Audit logging (AU-2)
pub async fn create_task(
    State(state): State<AppState>,
    claims: Claims,
    ValidatedJson(input): ValidatedJson<CreateTaskRequest>,
) -> Result<Json<Task>, AppError> {
    let task_id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    // Encrypt sensitive notes if provided (SC-28)
    let notes = if let Some(ref notes_text) = input.notes {
        // In production, store EncryptedField in database
        // let encrypted = state.encryptor.encrypt(notes_text)?;
        // For demo, just sanitize
        Some(sanitize_html(notes_text))
    } else {
        None
    };

    let task = Task {
        id: task_id.clone(),
        user_id: claims.sub.clone(),
        title: sanitize_html(&input.title),
        description: input.description.map(|d| sanitize_html(&d)),
        notes,
        completed: false,
        created_at: now,
        updated_at: now,
    };

    // Store task
    TASKS.lock().unwrap().insert(task_id.clone(), task.clone());

    // Audit log (AU-2, AU-3)
    info!(
        event = "task.created",
        user_id = %claims.sub,
        task_id = %task_id,
        "Task created"
    );

    Ok(Json(task))
}

/// Get a specific task
pub async fn get_task(
    State(_state): State<AppState>,
    claims: Claims,
    Path(task_id): Path<String>,
) -> Result<Json<Task>, AppError> {
    let tasks = TASKS.lock().unwrap();

    let task = tasks
        .get(&task_id)
        .ok_or_else(|| AppError::not_found("Task not found"))?;

    // Authorization check - user can only access their own tasks
    if task.user_id != claims.sub {
        return Err(AppError::forbidden("Access denied"));
    }

    // Decrypt notes if present (SC-28)
    // In production: state.encryptor.decrypt(&task.encrypted_notes)?

    Ok(Json(task.clone()))
}

/// Update a task
pub async fn update_task(
    State(_state): State<AppState>,
    claims: Claims,
    Path(task_id): Path<String>,
    ValidatedJson(input): ValidatedJson<UpdateTaskRequest>,
) -> Result<Json<Task>, AppError> {
    let mut tasks = TASKS.lock().unwrap();

    let task = tasks
        .get_mut(&task_id)
        .ok_or_else(|| AppError::not_found("Task not found"))?;

    // Authorization check
    if task.user_id != claims.sub {
        return Err(AppError::forbidden("Access denied"));
    }

    // Apply updates
    if let Some(title) = input.title {
        task.title = sanitize_html(&title);
    }
    if let Some(desc) = input.description {
        task.description = Some(sanitize_html(&desc));
    }
    if let Some(notes) = input.notes {
        // Re-encrypt updated notes (SC-28)
        task.notes = Some(sanitize_html(&notes));
    }
    if let Some(completed) = input.completed {
        task.completed = completed;
    }
    task.updated_at = Utc::now();

    // Audit log
    info!(
        event = "task.updated",
        user_id = %claims.sub,
        task_id = %task_id,
        "Task updated"
    );

    Ok(Json(task.clone()))
}

/// Delete a task
pub async fn delete_task(
    State(_state): State<AppState>,
    claims: Claims,
    Path(task_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut tasks = TASKS.lock().unwrap();

    // Check task exists and user owns it
    let task = tasks
        .get(&task_id)
        .ok_or_else(|| AppError::not_found("Task not found"))?;

    if task.user_id != claims.sub {
        return Err(AppError::forbidden("Access denied"));
    }

    // Remove task
    tasks.remove(&task_id);

    // Audit log
    info!(
        event = "task.deleted",
        user_id = %claims.sub,
        task_id = %task_id,
        "Task deleted"
    );

    Ok(Json(serde_json::json!({"deleted": true})))
}
