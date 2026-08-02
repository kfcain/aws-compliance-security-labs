# Publish this lab

This folder has no git history. Create a new repository when you publish:

```bash
git init -b main
git add .
git commit -m "Initial commit: lab-supply-chain-sbom"
gh repo create lab-supply-chain-sbom --public --source=. --remote=origin --push
```

Enable Pages from the repository root (`index.html`) or `/docs`.
