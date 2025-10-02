# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-10-02

### Added
- **Task Management System**: Complete task management functionality for reusable sync configurations
  - Create, store, and manage sync tasks with custom names (alphanumeric validation)
  - Tasks persist in SQLite database for reliable storage
  - Tasks tab in the web interface with intuitive task list and management
  - Task creation modal accessible from sync configuration screen
  - Task execution with play/delete buttons in the web interface
- **CLI Task Execution**: Command-line interface for automated task execution
  - `--start-task <task-name>` option to run tasks from command line
  - Real-time progress monitoring in CLI with formatted output
  - Automatic exit codes for success/failure states
  - Perfect for automation, cron jobs, and scripts
- **Database Layer**: SQLite integration for persistent data storage
  - Automatic database initialization and schema management
  - CRUD operations for task management
  - Future-ready architecture for additional features
- **REST API Endpoints**: New API endpoints for task management
  - `GET /api/tasks` - List all tasks
  - `POST /api/tasks` - Create new task
  - `DELETE /api/tasks/:id` - Delete task
  - `POST /api/tasks/start` - Start task by name
- **Enhanced Web Interface**: Improved frontend with task management
  - New Tasks tab with material design icons
  - Task creation modal with validation
  - Seamless integration with existing sync workflow
  - Real-time task status updates

### Technical Details
- Added SQLx crate for database operations with SQLite backend
- Implemented proper error handling and validation for task names
- Added database schema management with automatic table creation
- Extended existing sync system to support task-based execution
- Maintained backward compatibility with existing sync functionality

### Contributors
- Claude (Anthropic AI Assistant) - Task management system implementation
- Original author - Base rclone GUI application

### Usage Examples

**Create a Task (Web Interface):**
1. Navigate to File Browser → Select file/folder → Click "Sync"
2. Configure remote and destination settings
3. Click "Create Task" → Enter task name → Create

**Execute Task (Web Interface):**
1. Go to Tasks tab → Click play button on desired task

**Execute Task (Command Line):**
```bash
./rclone-gui --start-task my-backup-task
```

**List Available Options:**
```bash
./rclone-gui --help
```