# Publish this monorepo

```bash
cd aws-compliance-security-labs
gh auth login
gh repo create kfcain/aws-compliance-security-labs --public --source=. --remote=origin --push
```

Or from the git bundle artifact:

```bash
git clone aws-compliance-security-labs.bundle aws-compliance-security-labs
cd aws-compliance-security-labs
gh repo create kfcain/aws-compliance-security-labs --public --source=. --remote=origin --push
```

To re-export standalone `lab-*` repos:

```bash
./scripts/export-lab-repos.sh /tmp/compliance-lab-repos
```
