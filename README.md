# Device Compliance Companion

## Initial Installation Instructions
The following must be done only the first time you use it.

> **Note:** You may be prompted to enter your Mac password at various points. Total install time should be 10 minutes or less. If you run into errors, contact **Jay**.

1. **Open Terminal**
2. **Install Homebrew**
   - 2a. Check version by running this in Terminal:
     ```bash
     brew --version
     ```
   - 2b. If you don’t see something like `Homebrew 4.6.16`, run this in Terminal:
     ```bash
     /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
     ```
3. **Install Python**
   - 3a. Check version by running this in Terminal:
     ```bash
     python3 --version
     ```
   - 3b. If you don’t see something like `Python 3.11.5`, run this in Terminal:
     ```bash
     brew install python
     ```
4. **Install osquery**
   - 4a. Run this in Terminal:
     ```bash
     brew install osquery
     ```
   - 4b. Run this in Terminal:
     ```bash
     pip3 install osquery
     ```
5. **Download** `device-compliance-companion.py` file somewhere on your Mac (preferably **not** the Downloads folder).

---

## Instructions to Run Device Compliance Companion

1. In **Finder**, navigate to the folder where you saved `device-compliance-companion.py`.
2. **Right-click the folder** (not the file) and choose **New Terminal at Folder**.
3. Run this in Terminal:
   ```bash
   python3 device-compliance-companion.py