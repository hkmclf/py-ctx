import boto3
import json
import os


REGION = os.environ.get("AWS_REGION", "us-west-2")
SECRET_ID = "okta-prod/pulumi"


def run():
    sm = boto3.client("secretsmanager", region_name=REGION)
    resp = sm.get_secret_value(SecretId=SECRET_ID)
    print(json.dumps(json.loads(resp["SecretString"]), indent=2))
