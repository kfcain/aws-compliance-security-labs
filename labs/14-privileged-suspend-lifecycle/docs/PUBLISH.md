# Publish this lab

This folder has no git history. Create a new repository when you publish:

```bash
git init -b main
git add .
git commit -m "Initial commit: lab-privileged-suspend-lifecycle"
gh repo create lab-privileged-suspend-lifecycle --public --source=. --remote=origin --push
```

Enable Pages from the repository root (`index.html`) or `/docs`.
