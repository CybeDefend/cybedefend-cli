#!/bin/bash
# scripts/set-version.sh

set -e

# Vérifier que le script est exécuté avec une version en argument
if [ $# -ne 1 ]; then
  echo "Usage: $0 <new-version>"
  exit 1
fi

NEW_VERSION=$1

# Vérifier que la version suit le format SemVer
if ! [[ "$NEW_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Error: Version must follow semantic versioning (e.g., v1.0.0)"
  exit 1
fi

# Supprimer le préfixe "v" pour la version dans le fichier Go
PLAIN_VERSION=${NEW_VERSION#v}

VERSION_FILE="cmd/version.go"

# Vérifier si le fichier version.go existe
if [ ! -f "$VERSION_FILE" ]; then
  echo "Error: $VERSION_FILE does not exist."
  exit 1
fi

# Mettre à jour la constante Version dans version.go
echo "Updating $VERSION_FILE with version $PLAIN_VERSION..."
sed -i.bak -E "s/const Version = \".*\"/const Version = \"$PLAIN_VERSION\"/" "$VERSION_FILE"

# Supprimer le fichier de sauvegarde créé par sed
rm -f "${VERSION_FILE}.bak"

# Ajouter et committer les modifications
git add "$VERSION_FILE"
git commit -m "Update version to $NEW_VERSION"

# Taguer la nouvelle version et pousser les modifications
git tag "$NEW_VERSION"
git push origin "$NEW_VERSION"

echo "Version updated to $NEW_VERSION in $VERSION_FILE and pushed to remote."
echo "GitHub Actions will handle the build and release process."
