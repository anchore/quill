#!/usr/bin/env bash
set -ue

KEYCHAIN_NAME=$1

# This script does the same as going to Keychain Access and selecting "Add Keychain" to make the keychain visible
# under "Custom Keychains". This is done with "security list-keychains -s" for some reason. The downside
# is that this sets the search path, not appends to it, so you will loose existing keychains in the search path.
# This script adds all of the existing keychains plus the new one. This is truly terrible.

keychains=$(security list-keychains -d user)

keychainNames=();

for keychain in $keychains
do
  basename=$(basename "$keychain")
  keychainName=${basename::${#basename}-4}
  keychainNames+=("$keychainName")
done

echo "existing user keychains: ${keychainNames[@]}"

set -x
security -v list-keychains -s "${keychainNames[@]}" $KEYCHAIN_NAME
