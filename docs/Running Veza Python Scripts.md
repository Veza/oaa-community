
## Linux
### Setup
#### Verify Python3 Installation
Many current Linux distributions ship with `python3` installed by default. 

To verify that `python3` is installed on your system, run the following command:
```
which python3
which pip3
```

If the outputs are filesystem paths (ex: `/usr/bin/python3`), the applications are installed.

#### Installing Required Packages
Veza Python scripts may rely on external dependencies; if this is the case, the script package will include a `requirements.txt` file.

To ensure that the dependencies are installed, run the following command from the directory in which the `requirements.txt` file is located:
```
pip3 install -r requirements.txt
```

#### Setting Environment Variables
Veza Python scripts often require some variable input at run time (ex: API key, service URL).

Non-secret data can be passed to the script as arguments or set as environment variables, but sensitive data __must__ be set as an environment variable.

See the `README.md` packaged with a script for a description of required input data.

##### Temporary Environment Variables
Environment variables can be set temporarily from the Linux shell; these settings will last until the shell process in which they are set is terminated.

To temporarily set an environment variable from the Linux shell, run the following command:
```
export <variable_name>="<value>"
```

An example setting `VEZA_URL` to the FQDN of a Veza instance:
```
export VEZA_URL="https://example.vezacloud.com"
```

To verify currently set environment variables and their values, run the `env` command from the terminal.

To remove a currently set environment variable, run the following command:
```
unset <variable_name>
```

Unsetting the previously established `VEZA_URL` example:
```
unset VEZA_URL
```

##### Persistent Environment Variables
Environment variables can be set persistently in a number of ways, each with their own scope.

In each case, edit the relevant file and add the following line to set the new variable:
```
export <variable_name>="<value>"
```

- To set a persistent environment variable for only the currently logged-on user, edit `~/.bashrc` and add the export to the end of the file.
- To set a variable for all login shell sessions, edit `/etc/profile` and add the export to the end of the file.
- To set a system-wide variable, edit `/etc/environment` and add the export to the end of the file.

Current shell sessions will not reflect the file update immediately - to make use of the newly set variable, `source` the file first:
```
source ~/.bashrc
```

### Execution
To run the Veza Python script, `chmod` the file to make it executable, then execute it:
```
chmod +x <script_name>.py
./<script_name>.py
```

To pass additional parameters not set as environment variables when executing the script:
```
./<script_name>.py --<parmeter1_name> <parameter1_value> --<flag_parmeter>
```

An example of setting a parameter with a value along with a flag parameter:
```
./veza_script.py --veza_url https://example.vezacloud.com --debug
```

### Scheduling
Periodic executions of scripts can be configured to run via `cron` or via `systemd`, depending on your environment.
#### Cron
Scheduling via `cron` requires a line to be added to the `crontab`.

__Note__: `cron` executes commands without a login shell; environment variables set in `~/.bashrc` or `/etc/profile` will not be loaded.

To edit the `crontab`, run `crontab -e`, then add the following:
```
VEZA_URL="https://example.vezacloud.com"
VEZA_API_KEY="k124c021...fc1d281"
0 * * * * /usr/bin/python3 /path/to/<veza_script.py>
```

Some distributions do not honor environment variables set in the `crontab` file; in those cases, they can be set inline:
```
0 * * * * root env VEZA_URL="https://example.vezacloud.com" VEZA_API_KEY="k124c021...fc1d281" /usr/bin/python3 /path/to/<veza_script.py>
```

#### Systemd
Scheduling via `systemd` requires a timer unit file and a corresponding service unit file.

Begin by creating the timer unit file (`vim /etc/system/systemd/<veza_script>.timer`):
```
[Unit]
Description=Execute Veza Python Script Every Hour

[Timer]
OnCalendar=daily

Unit=<veza_script>.service

[Install]
WantedBy=timers.target
```

Then create the service file (`vim /etc/system/systemd/<veza_script>.service`):
```
[Unit]
Description=Veza Python Script Service

[Service]
# Environment variables can be defined here
Environment=VEZA_URL="https://example.vezacloud.com"
Environment=VEZA_API_KEY="k124c021...fc1d281"
Type=simple
ExecStart=/usr/bin/python3 /path/to/<veza_script.py>

[Install]
WantedBy=multi-user.target
```

Run the following commands to reload service definitions and enable the new service:
```
systemctl daemon-reload
systemctl enable <veza_script>.service
systemctl start <veza_script>.service
```


## Windows

### Setup
#### Verify Python Installation
Install python by browsing to https://www.python.org/downloads/windows/ and selecting the latest stable 64-bit installer.

Alternatively, on Windows workstations, Python may be installed via the __Microsoft Store__. See https://learn.microsoft.com/en-us/windows/python/beginners for details.

__Note__: During installation, ensure the `Add python.exe to PATH` checkbox is selected.

To ensure that python and pip are properly installed and added to the `PATH`, open a `Command Prompt` and run:
```
where python
where pip
```

Both commands will return paths on the filesystem if the executables are located.

#### Installing Required Packages
Veza Python scripts may rely on external dependencies; if this is the case, the script package will include a `requirements.txt` file.

To ensure that the dependencies are installed, run the following command from the directory in which the `requirements.txt` file is located:
```
pip install -r requirements.txt
```

#### Setting Environment Variables
##### Temporary Environment Variables
###### Command Prompt
To set an environment variable for an existing __Command Prompt__ session, run the following:
```
set <variable_name>=<value>
```

An example setting `VEZA_URL` to the FQDN of a Veza instance:
```
set VEZA_URL="https://example.vezacloud.com"
```

To remove the previously set `VEZA_URL` example:
```
set VEZA_URL=
```

###### Powershell
To set an environment variable for an existing __Powershell__ session, run the following:
```
$env:<variable_name> = '<value'
```

An example setting `VEZA_URL` to the FQDN of a Veza instance:
```
$env:VEZA_URL = 'https://example.vezacloud.com'
```

To remove the previously set `VEZA_URL` example:
```
Remove-Item env:\VEZA_URL
```
##### Persistent Environment Variables
To set environment variables on a Windows system, follow these steps:
- On the taskbar, right-click the Windows icon and click __System__
- In the __Settings__ window, locate and click __Advanced system settings__
- In the __System Properties__ window that appears, click the __Environment Variables__ button near the bottom.
- In the __Environment Variables__ window that appears, choose the scope for the new variable. User-specific variables are listed at the top of the window with system-wide variables below.
- Click the __New__ button underneath the appropriate scope.
- Complete the __New System Variable__ dialog that appears, providing a __Variable name__ and __Variable value__, then click __OK__
	__Note__: no quotes are required for complex variable values when set via this method

Current __Command Prompt__ and __Powershell__ sessions will not update immediately - to make use of the newly set variable, start a new __Command Prompt__ or __Powershell__ session.
### Execution
To run the Veza Python script, open a __Command Prompt__ window and execute the following:
```
python <script_name>.py
```

To pass additional parameters not set as environment variables when executing the script:
```
./<script_name>.py --<parmeter1_name> <parameter1_value> --<flag_parmeter>
```

An example of setting a parameter with a value along with a flag parameter:
```
./veza_script.py --veza_url https://example.vezacloud.com --debug
```

### Scheduling
Periodic executions of scripts can be configured via the __Task Scheduler__ interface on Windows.

__Note__: ensure that any required environment variables have been stored as system-wide variables before scheduling a task that utilizes them. 
Also terminate the `Taskeng.exe` process to force __Task Scheduler__ to reload environment variables.

- In the search bar, type `Task Scheduler`, then click on the search result to open the interface.
- In the __Actions__ pane on the right-hand side of the window, click __Create Basic Task__
- In the __Create Basic Task Wizard__, provide the following:
	- __Name__: A name for the scheduled task
	- __Description__: An optional longer description of what the task does
	- __Trigger__: Select a time-based trigger (`Daily`)
	- Daily time settings for task triggering
	- __Program/script__: Enter or browse to the installation location of the python executable
		- __Add arguments__: `<script_name>.py --<parameter1_name> <parameter1_value>`
		- __Start in__: `c:\path\to\script\`
## Mac

### Setup
#### Verify Python3 Installation
To install `python3` on Mac OS, ensure that Homebrew is installed and run the following command:
```
brew install python
```

To verify that `python3` is installed on your system, run the following command:
```
which python3
which pip3
```

If the outputs are filesystem paths (ex: `/usr/local/bin/python3`), the applications are installed.

#### Installing Required Packages
Veza Python scripts may rely on external dependencies; if this is the case, the script package will include a `requirements.txt` file.

To ensure that the dependencies are installed, run the following command from the directory in which the `requirements.txt` file is located:
```
pip3 install -r requirements.txt
```

#### Setting Environment Variables
Veza Python scripts often require some variable input at run time (ex: API key, service URL).

Non-secret data can be passed to the script as arguments or set as environment variables, but sensitive data __must__ be set as an environment variable.

See the `README.md` packaged with a script for a description of required input data.

##### Temporary Environment Variables
Environment variables can be set temporarily from the Linux shell; these settings will last until the shell process in which they are set is terminated.

To temporarily set an environment variable from the Linux shell, run the following command:
```
export <variable_name>="<value>"
```

An example setting `VEZA_URL` to the FQDN of a Veza instance:
```
export VEZA_URL="https://example.vezacloud.com"
```

To verify currently set environment variables and their values, run the `env` command from the terminal.

To remove a currently set environment variable, run the following command:
```
unset <variable_name>
```

Unsetting the previously established `VEZA_URL` example:
```
unset VEZA_URL
```

##### Persistent Environment Variables
Environment variables can be set persistently in a number of ways, each with their own scope.

In each case, edit the relevant file and add the following line to set the new variable:
```
export <variable_name>="<value>"
```

- To set a persistent environment variable for only the currently logged-on user, edit `~/.zshrc` and add the export to the end of the file.
- To set a variable for all login shell sessions, edit `/etc/profile` and add the export to the end of the file.

Current shell sessions will not reflect the file update immediately - to make use of the newly set variable, `source` the file first:
```
source ~/.zshrc
```

### Execution
To run the Veza Python script, `chmod` the file to make it executable, then execute it:
```
chmod +x <script_name>.py
./<script_name>.py
```

To pass additional parameters not set as environment variables when executing the script:
```
./<script_name>.py --<parmeter1_name> <parameter1_value> --<flag_parmeter>
```

An example of setting a parameter with a value along with a flag parameter:
```
./veza_script.py --veza_url https://example.vezacloud.com --debug
```

### Scheduling
#### Cron
Scheduling via `cron` requires a line to be added to the `crontab`.

__Note__: `cron` executes commands without a login shell; environment variables set outside of the `crontab` will not be loaded.

To edit the `crontab`, run `crontab -e`, then add the following:
```
VEZA_URL="https://example.vezacloud.com"
VEZA_API_KEY="k124c021...fc1d281"
0 * * * * /usr/bin/python3 /path/to/<veza_script.py>
```