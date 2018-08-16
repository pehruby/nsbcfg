# Netscaler configuration and monitoring utilities

## Installation

Clone github repository

```text
git clone https://github.com/pehruby/nsbcfg
```

Install virtual environment and activate it (optional)

```text
virtualenv nsbcfg --no-site-packages

cd nsbcfg
Scripts\activate
```

Install required packages

```text
pip install -r requirements.txt

or

py -3 -m pip install -r requirements.txt
```


### nsbcfg.py
[Netscaler batch configuration](nsbcfg.md)

Enables to maintain Netscaler configuration using YAML (or JSON) configuration files. The configuration files define configuration items (servers, monitors, LB vservers, CS vservers, ...) and their bindings. nsbcfg utility configures Netscaler using NITRO API according to the configuration files.


### nsstat.py
[Netscaler vserver statististics](nsstat.md)

Prints statistics related to specific vserver (status, hit count,...)


### getcertbind.py
[Netscaler certificate usage](getcertbind.md)

Prints certificate and all vservers which is this certificate binded to.




