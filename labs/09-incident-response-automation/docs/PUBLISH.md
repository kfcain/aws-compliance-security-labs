# Publish this lab

This folder has no git history. Create a new repository when you publish:

```bash
git init -b main
git add .
git commit -m "Initial commit: lab-incident-response-automation"
gh repo create lab-incident-response-automation --public --source=. --remote=origin --push
```

Enable Pages from the repository root (`index.html`) or `/docs`.
