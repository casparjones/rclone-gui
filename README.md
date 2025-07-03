# Rclone GUI

A Rust-based web application that provides a user-friendly GUI for rclone file synchronization.

## Features

- **Configuration Management**: Create, edit, and manage rclone remote configurations
- **File Browser**: Browse local files with an intuitive interface
- **Remote Browsing**: Navigate remote storage structures
- **Sync Functionality**: Upload files/folders to remotes with progress tracking
- **Memory Mode**: Optional in-memory configuration for safe testing

## Prerequisites

- Rust (latest stable version)
- rclone installed and accessible in PATH
- Web browser for the GUI

## Installation & Setup

1. Clone or download the source code
2. (Optional) Configure the default file browser path:
   ```bash
   # Edit .env file to set your preferred starting directory
   nano .env
   ```
3. Build the application:
   ```bash
   cargo build --release
   ```

## Usage

### Basic Usage
```bash
cargo run
```
This starts the server on `http://127.0.0.1:8080`

### Memory Mode (Testing)
```bash
cargo run -- --memory-mode
```
In memory mode, configurations are stored in RAM and not automatically saved to `rclone.conf`. Use the "Save to File" button to persist changes.

### Custom Bind Address
```bash
cargo run -- --bind 0.0.0.0:3000
```

### Command Line Options
- `--memory-mode`: Enable in-memory configuration mode
- `--bind <address>`: Set custom bind address (default: 127.0.0.1:8080)
- `--help`: Show all available options

## Web Interface

Open your browser to `http://127.0.0.1:8080` (or your custom bind address) to access the GUI.

### Configuration Tab
- **Add New Remote**: Create rclone configurations for various services
- **Supported Types**: WebDAV, S3, Dropbox, Google Drive, OneDrive, and more
- **Existing Configurations**: View and manage saved remotes
- **Save to File**: (Memory mode only) Persist configurations to rclone.conf

### File Browser Tab
- **Local Navigation**: Browse your local filesystem
- **Directory Tree**: Click folders to navigate
- **File Actions**: Each file/folder has a "Sync" button
- **Default Path**: Starts at `/mnt/home` (siehe Konfiguration unten)

### Sync Jobs Tab
- **Active Jobs**: Monitor ongoing sync operations
- **Progress Tracking**: Real-time progress bars and status updates
- **Job History**: View completed and failed sync operations

## Sync Process

1. Navigate to the desired local file/folder in the File Browser
2. Click the "Sync" button next to the item
3. Select the target remote from the dropdown
4. Navigate to the desired destination folder on the remote
5. Click "Start Upload"
6. Monitor progress in the popup or Sync Jobs tab

## Configuration File

The application creates/manages an `rclone.conf` file in the `data/cfg/` directory. This file follows the standard rclone configuration format and can be used with the rclone command-line tool.

**Wichtig**: 
- Alle rclone-Befehle verwenden automatisch den `--config data/cfg/rclone.conf` Parameter
- Neue Passwörter werden automatisch mit `rclone obscure` verschleiert gespeichert
- Bestehende Konfigurationen werden nicht automatisch verändert

## Konfiguration des File Browser Start-Ordners

Der File Browser startet standardmäßig im Ordner `/mnt/home`. Dieser kann über Umgebungsvariablen konfiguriert werden:

### Methode 1: .env Datei (empfohlen)
1. Bearbeiten Sie die Datei `.env` im Projektverzeichnis
2. Ändern Sie die Zeile: `RCLONE_GUI_DEFAULT_PATH=/mnt/home`
3. Setzen Sie Ihren gewünschten Start-Ordner, z.B.:
   ```bash
   RCLONE_GUI_DEFAULT_PATH=/home/user          # Linux/Mac Home-Ordner
   RCLONE_GUI_DEFAULT_PATH=/Users/username     # macOS-Benutzer
   RCLONE_GUI_DEFAULT_PATH=/                   # Root-Verzeichnis
   RCLONE_GUI_DEFAULT_PATH=/mnt/storage        # Eigener Mount-Point
   ```
4. Starten Sie die Anwendung neu

### Methode 2: Umgebungsvariable beim Start
```bash
RCLONE_GUI_DEFAULT_PATH=/home/user cargo run
# oder
RCLONE_GUI_DEFAULT_PATH=/home/user ./start.sh
```

### Methode 3: System-weite Umgebungsvariable
```bash
export RCLONE_GUI_DEFAULT_PATH=/home/user
cargo run
```

**Hinweis**: Stellen Sie sicher, dass der angegebene Pfad existiert und die Anwendung Leserechte darauf hat.

## Architecture

- **Backend**: Rust with axum web framework
- **Frontend**: Vanilla HTML/CSS/JavaScript
- **rclone Integration**: Uses `tokio::process::Command` for rclone operations
- **Configuration**: INI format parsing for rclone.conf
- **Progress Tracking**: Real-time job monitoring with polling

## Development

### Project Structure
```
src/
├── main.rs              # Application entry point
├── models.rs            # Data structures
├── config_manager.rs    # Configuration management
└── handlers/
    ├── mod.rs
    ├── config.rs        # Configuration API endpoints
    ├── files.rs         # File browser endpoints
    └── sync.rs          # Sync operation endpoints
static/
├── index.html           # Main web interface
└── app.js              # Frontend JavaScript
```

### Building
```bash
cargo build --release
```

### Running Tests
```bash
cargo test
```

## Security Notes

- The application binds to localhost by default for security
- Passwords are stored in plaintext in rclone.conf (standard rclone behavior)
- Use `--bind 0.0.0.0:port` only in trusted network environments
- Consider using rclone's built-in encryption for sensitive data

## Troubleshooting

### Common Issues

1. **"rclone not found"**: Ensure rclone is installed and in your PATH
2. **Permission errors**: Check file system permissions for the working directory
3. **Port already in use**: Use `--bind` to specify a different port
4. **Sync failures**: Check rclone.conf syntax and remote credentials
5. **"couldn't decrypt password"**: This error is now automatically fixed by password obscuring
6. **"didn't find section in config file"**: Check that the config name matches exactly
7. **Remote connection issues**: Verify URL, username, and password are correct
8. **"413 Request Entity Too Large"**: 
   - Use the built-in multi-threading feature for large files
   - Try conservative performance levels first
   - Check your cloud provider's upload limits
9. **Upload timeouts**: Enable multi-threading with conservative settings
10. **"unknown flag" errors**: Fixed - using only valid rclone flags

### Debug Mode
Set `RUST_LOG=debug` environment variable for detailed logging:
```bash
RUST_LOG=debug cargo run
```

## 🐋 Docker Deployment

### Lokales Docker Build
```bash
# Image bauen
docker build -t rclone-gui:latest .

# Mit Docker Compose starten
docker-compose up -d
```

### GitHub Container Registry
Siehe `Docker.info` für detaillierte Anweisungen zum Deployment über GitHub Container Registry.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is open source. Please ensure compliance with rclone's licensing terms when using this software.