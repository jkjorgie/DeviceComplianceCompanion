# Device Compliance Companion

## Initial Installation Instructions
The following must be done only the first time you use it.

> **Note:** You may be prompted to enter your Mac password at various points. Total install time should be ~20 minutes or less. If you run into errors, contact **Jay Jorgensen**.

1. **Open Terminal**
2. **Install Homebrew if you haven't already**
   - 2a. Check version:
     ```bash
     brew --version
     ```
   - 2b. If you don’t see something like `Homebrew 4.6.16`, run this in Terminal:
     ```bash
     /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
     ```
3. **Install Python if you haven't already**
   - 3a. Check version:
     ```bash
     python3 --version
     ```
   - 3b. If you don’t see something like `Python 3.11.5`, run this in Terminal:
     ```bash
     brew install python
     ```
4. **Install osquery if you haven't already**
   - 4a. Check version:
     ```bash
     osqueryi --version
     ```
   - 4b. If you don’t see something like `osqueryi version 5.19.0`, run this in Terminal:
     ```bash
     brew install osquery
     ```

---

## Instructions to Run Device Compliance Companion

1. **Download** the `device-compliance-companion.py` file somewhere on your Mac (preferably **not** the Downloads folder).
2. In **Finder**, navigate to the folder where you saved `device-compliance-companion.py`.
3. **Right-click the folder** (not the file) and choose **New Terminal at Folder**.
4. Run this in Terminal:
   ```bash
   python3 device-compliance-companion.py