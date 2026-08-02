# Publish this lab

This folder has no git history. Create a new repository when you publish:

```bash
git init -b main
git add .
git commit -m "Initial commit: lab-cloudtrail-evidence-pipeline"
gh repo create lab-cloudtrail-evidence-pipeline --public --source=. --remote=origin --push
```

Enable Pages from the repository root (`index.html`) or `/docs`.
