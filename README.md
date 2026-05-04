# AWS IAM Policy Classifier and Remediator

This project analyzes an AWS IAM policy JSON file with an LLM model (Gemini), classifies it as `Strong` or `Weak`, and generates a remediated policy when the input is weak.

## What the program does

- Performs preflight sanity-checks on the input before any analysis starts.
- Classifies the policy as `Strong` or `Weak`.
- Writes a classification JSON for every valid policy.
- Writes a remediated JSON only when the policy is classified as `Weak`.

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

3. Create and configure an `.env` file for the Gemini API.

```env
GEMINI_API_KEY=your_api_key_here
GEMINI_MODEL=gemini-2.5-flash
```

## Run the CLI

Analyze a policy and write outputs into the default `output` directory:

```powershell
python main.py --policy tests/sample_policies/weak1.json
```

Choose a custom output directory:

```powershell
python main.py --policy tests/sample_policies/strong1.json --output-dir custom-output
```

Show the step-by-step tool flow:

```powershell
python main.py --policy tests/sample_policies/weak1.json --verbose
```

## Gemini runtime behavior

- The agent decides which analysis tool to call next.
- Tool observations are fed back into the model.
- The model returns the final classification JSON.
- If the classification is `Weak`, the remediation tool makes a separate Gemini call that returns the remediated policy JSON.

## Output files

For a valid input policy, the CLI writes files under the selected output directory.

- `*_classification_*.json` is always written.
- `*_remediated_*.json` is written only when the policy is classified as `Weak`.

### Classification output fields

The classification JSON contains these key attributes:

- `classification`: The final verdict. `Strong` means no high-risk weaknesses were found. `Weak` means the tool found material IAM issues that violate least-privilege expectations.
- `reason`: A short human-readable summary of why the policy received that verdict.
- `findings`: A list of the concrete issues that drove the verdict. Each item identifies the statement, the weakness, and its severity.

Example shape:

```json
{
    "policy": { "...": "..." },
    "classification": "Weak",
    "reason": "This policy grants administrator-equivalent or otherwise overly broad Allow permissions.",
    "findings": [
        "Statement 0 (Statement0): Action '*' uses a wildcard pattern (CRITICAL)",
        "Statement 0 (Statement0): Resource scope is broad: * (HIGH)"
    ]
}
```

### Remediated output fields

When a policy is weak, the remediation JSON adds these key attributes:

- `changes`: A list of the edits the remediator made to tighten the policy. This is intended to be a concise change log.
- `reasoning`: A paragraph that explains the security rationale behind those edits and why they reduce risk.

The remediation JSON also includes `original_policy` and `remediated_policy` so you can compare the before and after documents directly.

Example shape:

```json
{
    "original_policy": { "...": "..." },
    "remediated_policy": { "...": "..." },
    "changes": [
        "Statement 0: replaced wildcard or inverted access logic with explicit S3 actions.",
        "Statement 0: scoped resources to example ARN patterns that should be replaced with real resource identifiers."
    ],
    "reasoning": "The original policy included overly broad Allow permissions that exceeded least-privilege expectations."
}
```

## Run tests

The LLM-facing tests use mocked Gemini clients - they do not require network access or a live API key.
Run the tests:

```powershell
python -m pytest -q
```