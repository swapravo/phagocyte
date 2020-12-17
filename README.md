# phagocyte
### Phagocyte is a self replicating program that attaches itself onto files and encrypts them, producing executables.
#### It has no dependencies and *should* be platform independent.

#### Usage:
    -h, --help    show this help message and exit
    -r            replicate the program
    -e E [E ...]  encrypt files
    -d            decrypt itself
    -s            delete the executable after decryption

#### Example:
    ./phagocyte.py -r
    ./phagocyte.py -e lisa.png
    ./lisa.png -ds (use "lisa" as password for the file in the example)
