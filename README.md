# AWS IAM Policy Classifier and Remediator

This project analyzes an AWS IAM policy JSON file, classifies it as `Strong` or `Weak`, and generates a remediated policy when the input is weak. The CLI uses a deterministic validation and analysis flow by default, and it can use Gemini for live agent and remediation calls when `GEMINI_API_KEY` is configured.

## What the program does

- Performs a preflight sanity-check before any analysis starts.
- Rejects malformed JSON files.
- Rejects parsed JSON that does not match expected AWS IAM policy attributes.
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

3. Create and configure an `.env` file if you want live model-backed analysis and remediation (Gemini).

```env
GEMINI_API_KEY=your_api_key_here
```

If `GEMINI_API_KEY` is not set, the program still runs using the built-in deterministic analysis and remediation flow.

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

## Input sanity-check behavior

The CLI validates the input in two stages before it starts the core policy analysis.

1. General JSON formatting check.
If the file is malformed JSON, the program exits immediately with a message that includes the parser failure and its line and column.

2. AWS IAM schema and attribute check.
If the JSON parses but does not use valid IAM policy attributes, the program exits immediately with a message describing the missing or unsupported IAM fields.

Examples in the repository:

- `tests/sample_policies/invalid1.json` fails the JSON formatting check.
- `tests/sample_policies/invalid2.json` fails the IAM attribute sanity-check.

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

Run the full test suite:

```powershell
python -m pytest -q
```

Run only the input-validation tests:

```powershell
python -m pytest tests/test_input_validation.py -q
```