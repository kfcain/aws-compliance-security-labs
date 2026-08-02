# Publish this lab

This folder has no git history. Create a new repository when you publish:

```bash
git init -b main
git add .
git commit -m "Initial commit: lab-federal-data-deletion-residual"
gh repo create lab-federal-data-deletion-residual --public --source=. --remote=origin --push
```

Enable Pages from the repository root (`index.html`) or `/docs`.
