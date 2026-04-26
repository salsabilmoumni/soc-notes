# Cloud Forensics — Field Notes

AWS CloudTrail and GCP log analysis using `jq`. Commands are built from real lab investigations.

---

## AWS CloudTrail — Setup

### Decompress log files
```bash
find . -type f -name "*.gz" -exec gunzip {} \;
```

### Find and hash all DLLs in extracted files
```bash
find . -type f -name "*.dll" -exec sha256sum {} \;
```

---

## AWS CloudTrail — jq queries

### Detect CloudTrail tampering (StopLogging / DeleteTrail)
```bash
find . -type f -name "*.json" -exec jq '
  .Records[] |
  select(.eventName == "StopLogging" or .eventName == "DeleteTrail") |
  {eventTime, eventSource, eventName, userIdentity, sourceIPAddress,
   trailArn, requestParametersName: .requestParameters.name}
' {} \;
```

### List all event names (get overview of activity)
```bash
find . -type f -exec cat {} \; | jq '.Records[].eventName'
```

### Build a sorted event timeline
```bash
find . -type f -exec cat {} \; | \
  jq -cr '.Records[][.eventTime, .eventName]|@tsv' | sort
```

### Filter by specific event names
```bash
find . -type f -exec cat {} \; | jq '
  .Records[] |
  select(.eventName == "DescribeInstances" or
         .eventName == "TerminateInstances" or
         .eventName == "StopInstances")
'
```

### Find failed AWS console logins (Splunk)
```splunk
index="aws_cloudtrail" eventSource="signin.amazonaws.com"
errorMessage="Failed authentication"
| stats count by userIdentity.userName
| sort - count
```

### Calculate total data exfiltrated via S3 GetObject
```bash
find . -type f -name "*.json" -exec jq -r '
  .events[] |
  .message |
  fromjson |
  select(.eventName == "GetObject" and
         .requestParameters.bucketName == "tourists-visa-info") |
  (.additionalEventData.bytesTransferredOut // 0)
' {} \; | awk '{sum += $1} END {
  print "Total bytes: " sum
  print "Total MB: " sum/1024/1024
  print "Total GB: " sum/1024/1024/1024
}'
```

---

## AWS key concepts for IR

| Concept | Notes |
|---|---|
| `ANONYMOUS_PRINCIPAL` in userIdentity | S3 bucket was publicly accessible — no auth required |
| `AssumedRole` user type | Attacker used temporary credentials from IAM role assumption |
| `GetObject` event | Object retrieved from S3 — check `bytesTransferredOut` |
| `DeleteObject` / `DeleteBucket` | Attacker covering tracks after exfiltration |
| `CreateLoginProfile` with `passwordResetRequired: false` | Attacker created console access without forced password reset |
| `GetCallerIdentity` | Attacker confirming their IAM role — equivalent to `whoami` |

### SSRF → IMDSv1 credential theft chain
```
1. Attacker finds SSRF vulnerability in web app
2. Crafts request to http://169.254.169.254/latest/meta-data/iam/security-credentials/
3. Retrieves temporary IAM role credentials (AccessKeyId, SecretAccessKey, Token)
4. Uses credentials with AWS CLI to enumerate environment
5. aws sts get-caller-identity  ← confirms access level
6. Lists S3 buckets → exfiltrates data
```

> **Detection:** Look for `GetCallerIdentity` calls from unexpected source IPs, followed by `ListBuckets` and `GetObject` in short succession.

---

## GCP Log Analysis — jq queries

### List all buckets accessed
```bash
jq '.[] |
  select(.protoPayload.resourceName != null and
         (.protoPayload.resourceName | contains("buckets"))) |
  {bucket: .protoPayload.resourceName,
   user: .protoPayload.authenticationInfo.principalEmail}
' logs.json
```

### Find objects accessed in a specific bucket
```bash
jq '.[] |
  select(.protoPayload.resourceName != null and
         (.protoPayload.resourceName | test("/buckets/confidential-documents-482374561/"))) |
  {bucket: (.protoPayload.resourceName | split("/")[3]),
   object: .protoPayload.resourceName}
' logs.json
```

### Find Compute Engine instances accessed by a specific user
```bash
jq '.[] |
  select(
    .protoPayload.authenticationInfo.principalEmail == "david.smith8392173781@gmail.com" and
    .protoPayload.serviceName == "compute.googleapis.com" and
    .protoPayload.authorizationInfo[].resource? != null and
    (.protoPayload.authorizationInfo[].resource | contains("/instances/"))
  ) |
  .protoPayload.authorizationInfo[].resource
' logs.json
```

### Find service account used by a Compute Engine instance
```bash
jq '.[] |
  select(.protoPayload.authenticationInfo.serviceAccountDelegationInfo != null) |
  {instance: .protoPayload.resourceName,
   serviceAccount: .protoPayload.authenticationInfo.principalEmail}
' logs.json
```

### Find Cloud SQL database targeted for export
```bash
jq '.[] |
  select(
    .protoPayload.authenticationInfo.principalEmail == "attacker@gmail.com" and
    .protoPayload.serviceName == "cloudsql.googleapis.com"
  ) |
  {database: .protoPayload.resourceName,
   user: .protoPayload.authenticationInfo.principalEmail}
' logs.json
```

### Find failed SQL export attempt (which bucket was targeted)
```bash
jq '.[] |
  select(
    .protoPayload.resourceName != null and
    (.protoPayload.resourceName | contains("analytics-db")) and
    (.protoPayload.authorizationInfo[].permission == "cloudsql.instances.export")
  ) |
  {uri: .protoPayload.resourceName, message: .protoPayload.status.message}
' logs.json
```

### Detect attacker-created service account (persistence)
```bash
jq '.[] |
  select(.protoPayload.methodName == "google.iam.admin.v1.CreateServiceAccount") |
  {createdBy: .protoPayload.authenticationInfo.principalEmail,
   serviceAccountId: .protoPayload.request.account_id}
' logs.json
```

### Detect service account key generation (persistence)
```bash
jq '.[] |
  select(.protoPayload.methodName == "google.iam.admin.v1.CreateServiceAccountKey") |
  {createdBy: .protoPayload.authenticationInfo.principalEmail,
   serviceAccountId: .protoPayload.response.name}
' logs.json
```

---

## GCP key concepts for IR

| Concept | Notes |
|---|---|
| `CreateServiceAccount` | Attacker creating persistent backdoor identity |
| `CreateServiceAccountKey` | Generates secret key for programmatic access without re-auth |
| `google.iam.admin.v1.*` | Any IAM admin method warrants scrutiny |
| `cloudsql.instances.export` | Attempted database export — check destination bucket |
| `compute.googleapis.com` | Compute Engine activity — check for crypto mining or lateral movement |

---

## MSI stream analysis

List streams inside an MSI file:
```bash
msiinfo streams file.msi
```

Extract a specific stream:
```bash
msiinfo extract file.msi stream_name > output_file
```

Check DLL hashes from extracted streams:
```bash
find . -type f -name "*.dll" -exec sha256sum {} \;
```
