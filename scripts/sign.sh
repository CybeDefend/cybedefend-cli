#!/bin/bash
# scripts/sign.sh

set -e

# Vérifiez si la clé de signature est disponible
if [ -z "$SIGNING_KEY" ] || [ -z "$SIGNING_KEY_PASSPHRASE" ]; then
  echo "Error: SIGNING_KEY or SIGNING_KEY_PASSPHRASE not set."
  exit 1
fi

# Importer la clé GPG
echo "Importing GPG key..."
echo "$SIGNING_KEY" | gpg --batch --import

# Signer chaque fichier dans le répertoire dist
for file in dist/*; do
  if [ -f "$file" ]; then
    echo "Signing $file..."
    echo "$SIGNING_KEY_PASSPHRASE" | gpg --batch --yes --passphrase-fd 0 --output "$file.sig" --detach-sign "$file"
  fi
done

echo "All files signed successfully."
