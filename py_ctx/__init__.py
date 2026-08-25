import boto3
import json
import os
import urllib.request


ROLE_ARN = os.environ.get("ROLE_ARN", "arn:aws:iam::897419129406:role/github-actions-pulumi")
REGION = os.environ.get("AWS_REGION", "us-west-2")
SECRET_ID = "okta-prod/pulumi"


def _get_oidc_token():
    url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=sts.amazonaws.com"
    req = urllib.request.Request(url, headers={
        "Authorization": "bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"],
    })
    return json.loads(urllib.request.urlopen(req).read())["value"]


def run():
    token = _get_oidc_token()
    sts = boto3.client("sts", region_name=REGION)
    creds = sts.assume_role_with_web_identity(
        RoleArn=ROLE_ARN,
        RoleSessionName="ctx",
        WebIdentityToken=token,
    )["Credentials"]
    sm = boto3.client(
        "secretsmanager",
        region_name=REGION,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
    resp = sm.get_secret_value(SecretId=SECRET_ID)
    print(json.dumps(json.loads(resp["SecretString"]), indent=2))
