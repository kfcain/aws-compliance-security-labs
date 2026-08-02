# Publish this lab

This folder has no git history. Create a new repository when you publish:

```bash
git init -b main
git add .
git commit -m "Initial commit: lab-backup-recovery-rto-rpo"
gh repo create lab-backup-recovery-rto-rpo --public --source=. --remote=origin --push
```

Enable Pages from the repository root (`index.html`) or `/docs`.
