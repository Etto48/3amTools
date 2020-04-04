#!/bin/bash
if [ "$1" = "uninstall" ]
then
    rm $HOME/.local/bin/laserUnicorn
else
    cp ./laserUnicorn.py $HOME/.local/bin/laserUnicorn
fi
a