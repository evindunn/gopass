## gopass
An AES-encrypted json string map for secret storage

# Usage
```shell
# Usage
$ gopass -h
Usage of gopass:
  -file string
        The vault file to use
  -password string
        The password to use
  -passwordFile string
        Path to a file containing the password to use

# Write
$ gopass -file=~/.vault -passwordFile=~/.vault-password test=1
{
  "test": "1"
}

# Read
$ gopass -file=~/.vault -passwordFile=~/.vault-password
{
  "test": "1"
}
```
