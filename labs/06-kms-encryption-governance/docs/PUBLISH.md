# Publish this lab

This folder has no git history. Create a new repository when you publish:

```bash
git init -b main
git add .
git commit -m "Initial commit: lab-kms-encryption-governance"
gh repo create lab-kms-encryption-governance --public --source=. --remote=origin --push
```

Enable Pages from the repository root (`index.html`) or `/docs`.
