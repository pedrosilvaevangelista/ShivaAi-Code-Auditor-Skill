# gRPC & Protobuf Attack Surface

**Tags:** #high #grpc #protobuf #api #microservices
**OWASP:** API Security Top 10
**CVSS Base:** 6.5 (Medium/High)

---

## 📖 What it is

gRPC is a high-performance RPC framework using HTTP/2 and Protocol Buffers (protobuf) for binary serialization. While it is more structured than JSON, it introduces specific vulnerabilities, especially when its reflection API is exposed, channels are insecurely configured, or protobuf parsing logic is manipulated.

---

## 🔍 `grep_search` Tactics

```
import "grpc"
grpc.Server(
add_reflection
reflection.Register
InsecureChannel
WithInsecure
WithTransportCredentials(insecure.NewCredentials())
channelz
.proto
```

---

## 💣 Attack Category 1: Reflection API Exposure

The Server Reflection API allows clients to query the server for its exposed services and methods, acting similarly to a WSDL or GraphQL Introspection query. Enabling this in production hands the attacker a complete blueprint of the internal Microservice mesh.

**Vulnerable Logic (Go):**
```go
import "google.golang.org/grpc/reflection"

s := grpc.NewServer()
pb.RegisterGreeterServer(s, &server{})
// CRITICAL FLAG  Reflection enabled in production
reflection.Register(s)
```

**Attack Execution:** An attacker uses tools like `grpcurl` or `grpcui` to map and interact with internal APIs that aren't authenticated properly because they assume "internal network trust."
`grpcurl -plaintext <target>:50051 list` -> dumps all services.

---

## 💣 Attack Category 2: Insecure Channels and Downgrade

Microservices intercommunicate frequently. If they configure gRPC connections using insecure channels, the traffic is sent over cleartext, making it vulnerable to interception or manipulation on the internal network.

**Vulnerable Logic (Node.js):**
```javascript
const client = new hello_proto.Greeter('localhost:50051', 
    // Data in transit unencrypted
    grpc.credentials.createInsecure() 
);
```

**Detection:** Look for `WithInsecure()` or `createInsecure()` methods in production connection pools. Note: Internal environments running service meshes like Istio should have mTLS enforced at the proxy level.

---

## 💣 Attack Category 3: Large Protobuf Payloads & Message Nesting

Protobuf serializers can consume large amounts of CPU and memory. Highly nested protobuf messages (Depth limits) can trigger a DoS event.

**Vulnerable Payload:**
A malicious `.proto` message constructed to have recursive elements without depth validation.

**Detection:** Verify if the gRPC server configures `MaxReceiveMessageSize` to a reasonable bound, preventing large buffer allocations.

---

### [NEW] Protobuf Type Confusion
**How it works:** If a server uses a loose decoder or is vulnerable to type-confusion during deserialization, an attacker might send a message with a different type than expected to trigger unintended code paths.

### [NEW] gRPC Smuggling (v2 over v1.1)
**How it works:** Similar to HTTP Smuggling, but happens when a proxy decodes HTTP/2 (gRPC) and forwards it as HTTP/1.1 to a legacy back-end.

---

## 🛡️ Fix

1. **Disable Reflection:** Never use `reflection.Register(s)` in production code. Use environmental flags.
2. **Channel Security:** Always use `grpc.credentials.createSsl()` or rely on strict service mesh mTLS policies.
3. **Payload Limits:** Configure `MAX_RECEIVE_MESSAGE_LENGTH`.

---

## 📌 References
- [[mobile-api-security-surface]]
- [gRPC Security Standards](https://grpc.io/docs/guides/auth/)
