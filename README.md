# ai-security-agent
Ai security agent for ubuntu systems

# The Goal
The goal of this system, is to allow a light-weight real-time security agent handle attacks, nono-bots and/or others attempting to execute dangerous executions that exists logged on your system by the day you allow open ports and/or your newly bought LTS machine.

You are constantly under botnet scans, SSHD attacks and/or others.
This system will take care of them for you, while informing you of what it does, what it finds

# Installation
```
1. install python-is-python3 ( if missing ):
sudo apt install python-is-python3

2. Sanity check
ls -l venv/bin (ensure activate exists)
which python3
python3 --version

3. Create venv (if not exists):
python3 -m venv venv

4. Activate:
source venv/bin/activate
(or . venv/bin/activate)

4.1. run requirements installation
pip install -r requirements.txt

5. Then run:
python3 agent.py
(or python agent.py once python points to 3.x)
```

# Contributing
```
To contibute, create a pull-request, with a well explained reason of why, what and how your change will make the ai better and/or solve an issue.
```
