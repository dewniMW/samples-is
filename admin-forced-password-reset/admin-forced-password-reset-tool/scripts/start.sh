#!/usr/bin/env bash

read -p "Enter host address of WSO2 IS (Required) (ex: https://localhost/9443) : " host
[ -z "$host" ] && { echo "Error: Host address can't be empty!"; exit 1; }
read -p "Enter username (Required) : " username
[ -z "$username" ] && { echo "Error: username can't be empty!"; exit 1; }
stty -echo
read -p "Enter password (Required) : " password
[ -z "$password" ] && { password=none; }
stty echo
echo

java -jar $(find . -name "*admin.forced.password.reset.tool*") $host $username $password $csv $attributes $excludedAttributes
