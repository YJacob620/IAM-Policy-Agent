# AWS IAM Policy Classifier and Remediator

This project analyzes AWS IAM policy JSON files with Gemini, classifies policies as Strong or Weak, and remediates weak policies.

## Setup (Windows)

1. Create and activate a virtual environment.

```powershell
python -m venv .venv
.\.venv\Scripts\activate
```

2. Install dependencies.

```powershell
pip install -r requirements.txt
```

3. Create a .env file.

```env
GEMINI_API_KEY=your_api_key_here
GEMINI_MODEL=gemini-flash-lite-latest          # or another model if desired
```

## Commands

### Normal workflow

```powershell
python main.py analyze --policy tests/sample_policies/weak1.json
```

Optional flags:

```powershell
python main.py analyze --policy tests/sample_policies/weak1.json --output-dir output --verbose
```

### Remediation-only recovery mode

Use this when classification already succeeded but remediation failed, and you want to retry only the second Gemini call using a prebuilt prompt file.

```powershell
python main.py remediate-from-prompt --policy tests/sample_policies/weak1.json --prompt-file remediation_prompt.txt
```

Optional flags:

```powershell
python main.py remediate-from-prompt --policy tests/sample_policies/weak1.json --prompt-file remediation_prompt.txt --output-dir output --verbose
```

## Runtime behavior

Normal analyze flow:

1. Validate and normalize input policy.
2. Run all deterministic analysis tools at once.
3. Send policy plus tool output to the classifier agent.
4. Save the classification artifact.
5. If classification is Weak, call remediation and save a remediated artifact.

Recovery flow:

1. Validate and normalize input policy.
2. Read full remediation prompt contents from the provided txt file.
3. Run remediation only (classification is skipped).
4. Save only the remediated artifact.

## Output files

- *_classification_*.json: always written by analyze mode.
- *_remediated_*.json: written after remediation runs successfully.

## Run tests

```powershell
python -m pytest -q
```
