# Scripts

Generate local demo identity material with:

```text
python scripts/generate_node_keys.py --node-id edge-1 --output-dir secrets
```

The script writes an unencrypted PKCS#8 PEM private key and a canonical
standard-base64 raw public key, refuses overwrites and symlink targets, and does
not print private key bytes. The output directory and generated files are local
state and must never be committed; production key custody is out of scope.
