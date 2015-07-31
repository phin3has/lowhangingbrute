# lowhangingbrute
Auto detect and brute force SSH, SMB, and MSSQL logins

#Requirements
* Masscan
* Metasploit


# Install 
```
git clone https://github.com/awhitehatter/lowhangingbrute.git
```

_IMPORTANT: First use update the main function (see line 234) with the correct paths to the required username/password lists_



# Usage
```python
python lowhangingbrute.py <ip/subnet>
```

The ```<ip/subnet>``` entry needs to be a valid masscan friendly entry, I do not validate this.

```python
python lowhangingbrute.py 10.0.0.0/8
```


