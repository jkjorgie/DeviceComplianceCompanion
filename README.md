# Device Compliance Companion

This script replaces the Drata agent for our quarterly device compliance check. It runs only when you run it. Nothing stays installed or running in the background.

In one run it:

1. Checks your Mac's security settings and shows the results.
2. Takes a screenshot of the results.
3. Opens the Passwords app and takes a screenshot of it.
4. Opens an email to the security admin with everything attached.

**Nothing is sent automatically.** You look at the email and click Send.

Do this **once at the beginning of every quarter** (early January, April, July, and October).

## First-time setup

1. Download `device-compliance-companion.py` from its hosted location at GT.
2. Move it out of Downloads into a folder you will keep, for example a `Compliance` folder inside Documents.

That's it. Nothing else to install.

## Running the check

1. In **Finder**, open the folder where you saved the script.
2. Right-click the folder and choose **New Terminal at Folder**. (If you don't see that option, open Terminal from Applications > Utilities, type `cd `, drag the folder onto the Terminal window, and press Return.)
3. Type this and press Return:

   ```
   python3 device-compliance-companion.py
   ```

4. The first time only, macOS may pop up a window offering to install **Command Line Tools**. Click **Install**, wait for it to finish (a few minutes), then go back to step 3.
5. The results appear. Every line under **Required checks** should say **OK**. If any says **NOT OK**, see *If something says NOT OK* below.
6. The first time only, macOS asks whether Terminal can **record the screen**. Click **Allow**, then go back to step 3. Without this the screenshots are blank.
7. The **Passwords** app opens. Unlock it with Touch ID or your password so your list of passwords is showing. Then click back on the Terminal window and press Return.
8. The first time only, macOS asks whether Terminal can control **Outlook** (or Mail). Click **Allow**.
9. An email opens, addressed to the security admin, with the results and both screenshots attached. Check that the screenshots look right, then click **Send**.

A copy of everything is also saved in **Documents > Device Compliance Evidence**, in a folder named for the quarter.

## If something says NOT OK

Fix the setting, then run the check again from step 3 before sending.

| Check | It passes when | Where to fix it |
|---|---|---|
| Gatekeeper | Apps are not allowed from "Anywhere" | System Settings > Privacy & Security > Security |
| Screen lock | Your Mac locks within 15 minutes of walking away and asks for a password | System Settings > Lock Screen. Set "Start Screen Saver when inactive" and "Require password after screen saver begins" so the two together are 15 minutes or less. |
| Security Responses + System Files | Both automatic install options are on | System Settings > General > Software Update > click the (i) next to Automatic Updates |
| FileVault | On | System Settings > Privacy & Security > FileVault |

## If something goes wrong

- **The screenshots show only your desktop.** Terminal needs permission to record the screen. Open System Settings > Privacy & Security > Screen & System Audio Recording, turn on Terminal, and run the check again.
- **No email opens.** Terminal needs permission to control Outlook or Mail. Open System Settings > Privacy & Security > Automation, and turn on Outlook (or Mail) under Terminal. If it still doesn't work, the script opens the evidence folder in Finder so you can attach the files to an email yourself.
- **The script asks you to click on a window.** It couldn't find the window on its own. Just click the window it names.
- **"Building the window-capture helper" appears.** Normal on the first run. It takes about ten seconds and won't happen again.
- **Anything else:** contact **Jay**.

## For the security admin

- The results header shows the script version and a SHA-256 of the script file. That identifies which version produced the report. It is not tamper evidence, since a modified script could print any value.
- A JSON file with the raw values behind each check is attached alongside the readable report.
- The Passwords screenshot is taken by the person running the script after they unlock the app. The script cannot read anything inside Passwords.

## Advanced

You don't need any of this for the normal quarterly check.

Two optional checks, firewall and pending macOS updates, are part of the Drata baseline but are not currently required. They are off by default. Add `--all-checks` to include them. They are shown for information and never cause a NOT OK result.

| Add to the command | Effect |
|---|---|
| `--check-only` | Show the results only. Saves nothing, opens nothing. |
| `--all-checks` | Also run the firewall and pending-updates checks. |
| `--to someone@example.com` | Address the email to someone else. |
| `--mail-app mail` | Create the email in Apple Mail instead of Outlook. (`--mail-app outlook` forces Outlook.) Without this, Outlook is used when installed, otherwise Apple Mail. |
| `--no-screenshots` | Skip both screenshots. |
| `--no-email` | Save the evidence and open the folder, but don't create an email. |
| `--evidence-dir DIR` | Save evidence somewhere other than Documents. |
| `--json` | Print the results as JSON. |
| `--no-color` | Plain text output. |

**Optional reminder.** If you would rather be prompted, `--install-schedule` sets up a daily 9:00 check that opens Terminal and runs everything when a new quarter's evidence is missing. This is the one feature that does keep something registered on your Mac, so it is off unless you ask for it. `--uninstall-schedule` removes it.

The script exits with code 0 when all required checks pass and 2 otherwise.
