# Publish this lab

This folder has no git history. Create a new repository when you publish:

```bash
git init -b main
git add .
git commit -m "Initial commit: lab-config-drift-compliance"
gh repo create lab-config-drift-compliance --public --source=. --remote=origin --push
```

Enable Pages from the repository root (`index.html`) or `/docs`.
