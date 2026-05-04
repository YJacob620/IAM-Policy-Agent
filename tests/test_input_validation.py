from __future__ import annotations

import json
from pathlib import Path

import pytest

from utils.file_io import IamPolicyValidationError, JsonFormattingError, load_policy


FIXTURE_DIR = Path(__file__).parent / "sample_policies"


def test_load_policy_rejects_invalid_json_formatting() -> None:
    with pytest.raises(JsonFormattingError, match="Invalid JSON formatting"):
        load_policy(FIXTURE_DIR / "invalid1.json")


def test_load_policy_rejects_invalid_iam_attributes() -> None:
    with pytest.raises(IamPolicyValidationError) as exc_info:
        load_policy(FIXTURE_DIR / "invalid2.json")

    message = str(exc_info.value)
    assert "Missing required IAM attribute 'Statement'" in message
    assert "Unsupported IAM attribute 'Ve123542d3rsion'" in message
    assert "Unsupported IAM attribute 'Stateme12343werasdwe54qnt'" in message


def test_load_policy_rejects_unknown_statement_attribute(tmp_path: Path) -> None:
    invalid_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Ac23rction": "s3:GetObject",
                "Resource": "arn:aws:s3:::example-bucket/*",
            }
        ],
    }
    policy_path = tmp_path / "invalid_statement.json"
    policy_path.write_text(json.dumps(invalid_policy), encoding="utf-8")

    with pytest.raises(IamPolicyValidationError) as exc_info:
        load_policy(policy_path)

    message = str(exc_info.value)
    assert "Unsupported IAM attribute 'Ac23rction' at Statement[0]" in message
