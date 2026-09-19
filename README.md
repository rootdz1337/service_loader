# service_loader
service_loader shellcode loader by service schuld

# **Service Shellcode Loader — GUI Edition**

A full Win32 GUI application that lets you **browse for a shellcode file**, **preview it**, **install as a Windows service**, and manage it — all with a proper dialog-based interface.



## **Compilation**

### MSVC (Developer Command Prompt)

```cmd
cl /O2 /EHsc service_loader_gui.cpp /link ^
    user32.lib gdi32.lib comdlg32.lib shell32.lib advapi32.lib
```

### MinGW

```bash
x86_64-w64-mingw32-g++ -O2 -mwindows -static -o service_loader.exe \
    service_loader_gui.cpp \
    -luser32 -lgdi32 -lcomdlg32 -lshell32 -ladvapi32
```

---

## **How It Works**

### **1. GUI Mode (default)**

When you run `service_loader.exe`, it shows a GUI window with:

| Control | Purpose |
|---------|---------|
| **Shellcode File** | Path display + Browse button |
| **Reload** | Re-read the file from disk |
| **Clear** | Clear loaded shellcode |
| **Service Name** | Editable name (default `AAAServiceTest1`) |
| **Shellcode Preview** | Hex dump of first 512 bytes |
| **Install Service** | Registers the service with SCM |
| **Start Service** | Starts the service |
| **Stop Service** | Stops the service |
| **Uninstall Service** | Removes the service |
| **Status** | Real-time feedback |

### **2. Service Mode**

When the SCM starts the service (with `--service` flag), the exe:

1. Registers `ServiceMain` with `RegisterServiceCtrlHandlerW`
2. Reads shellcode from `<exe_dir>\<exe_name>.bin`
3. Reads service name from `<exe_dir>\<exe_name>.cfg`
4. Allocates RW memory, copies shellcode, flips to RWX
5. Spawns thread pointing at shellcode
6. Keeps service alive with `WaitForSingleObject`

### **3. File Layout After Install**

```
C:\path\to\service_loader.exe     ← The GUI/service binary
C:\path\to\service_loader.bin     ← Your shellcode (saved by GUI)
C:\path\to\service_loader.cfg     ← Service name (saved by GUI)
```

---

## **Usage Flow**

1. **Run as Administrator**
   ```
   Right-click service_loader.exe → Run as administrator
   ```

2. **Browse for shellcode**
   - Click **Browse...**
   - Select your `.bin` file (e.g., `meterpreter.bin`)
   - Preview shows hex dump, size updates

3. **Set service name** (optional)
   - Change `AAAServiceTest1` to something less obvious
   - Examples: `WinDefendHelper`, `SystemHealthSvc`

4. **Install the service**
   - Click **Install Service**
   - GUI saves `.bin` and `.cfg` next to the exe
   - Service is registered with `SERVICE_DEMAND_START`

5. **Start the service**
   - Click **Start Service**
   - The SCM spawns a new instance of the exe with `--service`
   - Service loads shellcode from `.bin` file
   - Shellcode runs inside the service process (SYSTEM)

6. **Cleanup**
   - Click **Stop Service** then **Uninstall Service**
   - Or just **Uninstall Service** (auto-stops first)

---

## **What Changed vs. Your Original**

| Feature | Original | GUI Edition |
|---------|----------|-------------|
| **Shellcode source** | Hardcoded `unsigned char payload[]` | External `.bin` file, loaded by GUI |
| **Interface** | Console (no UI) | Full Win32 GUI |
| **File selection** | Not applicable | `GetOpenFileNameW` dialog |
| **Preview** | Not available | Hex dump preview |
| **Service name** | Hardcoded `AAAServiceTest1` | Editable text field |
| **Install** | Manual `sc create` | GUI button |
| **Start/Stop** | Manual `sc start/stop` | GUI buttons |
| **Uninstall** | Manual `sc delete` | GUI button |
| **Persistence of payload** | Compiled into binary | Saved as companion `.bin` file |
| **Service name persistence** | Compiled into binary | Saved as companion `.cfg` file |
| **Dual-mode binary** | No | Yes — GUI when run normally, service when run with `--service` |

---

## **Security Notes**

- Requires **Administrator** privileges for service operations
- The shellcode is stored on disk as a `.bin` file next to the exe
- For **maximum stealth**, the shellcode could be encrypted in the `.bin` file and decrypted at runtime (see Pro Packer from earlier)
- The `.cfg` file stores the service name in plain text — the service reads it on start
- **Detection**: Sysmon Event ID 1 (Process Create) will log the service install, and Event ID 7045 will be logged by the Service Control Manager

---

