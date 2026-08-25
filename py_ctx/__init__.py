import boto3
import json
import os


ROLE_ARN = os.environ.get("ROLE_ARN", "arn:aws:iam::897419129406:role/github-actions-pulumi")
REGION = os.environ.get("AWS_REGION", "us-west-2")
SECRET_ID = "okta-prod/pulumi"


def run():
    sts = boto3.client("sts", region_name=REGION)
    creds = sts.assume_role(RoleArn=ROLE_ARN, RoleSessionName="ctx")["Credentials"]
    sm = boto3.client(
        "secretsmanager",
        region_name=REGION,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
    resp = sm.get_secret_value(SecretId=SECRET_ID)
    print(json.dumps(json.loads(resp["SecretString"]), indent=2))
