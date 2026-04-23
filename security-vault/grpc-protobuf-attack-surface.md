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
MessageFactory
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

## 💣 Attack Category 4: Protobuf Type Confusion
**How it works:** Protobuf uses field tags (integers 1, 2, 3) instead of field names to deserialize data. If a client sends a message where a field tag corresponds to a string, but the server code uses a loose decoder (like converting protobuf directly to JSON without a strict schema) and interprets it as an array or a different object, it can bypass input validation.
**Attack Execution:** Sending unexpected wire types (`VARINT` vs `LENGTH_DELIMITED`) to crash the parser, or exploiting dynamic message factories (`DynamicMessage`) that instantiate arbitrary types based on input.
**`grep_search`:** `DynamicMessage.parseFrom`, `JsonFormat.parser()`.

---

## 💣 Attack Category 5: gRPC Smuggling (HTTP/2 to HTTP/1.1)
**How it works:** gRPC runs over HTTP/2. If an API Gateway or Reverse Proxy (e.g., an older Nginx or HAProxy) sits in front of the gRPC server and attempts to decode the HTTP/2 frames, it might misinterpret the gRPC headers (like `grpc-status` or trailers). 
**Attack Execution:** An attacker smuggles a secondary request inside the gRPC data frame payload if the proxy improperly forwards the HTTP/2 stream as a chunked HTTP/1.1 request to a backend that expects REST.
**`grep_search`:** `proxy_http_version 1.1;` mixed with `grpc_pass`.

---

## 💣 Attack Category 6: Unary vs Streaming Smuggling
**How it works:** In gRPC, unary requests are treated as standard HTTP/2 streams. However, bi-directional streams can be kept open for a long time. 
**Attack Execution:** If an attacker opens a bi-directional stream but sends malformed frame boundaries, poorly configured Envoy or Istio proxies might drop the authentication context but keep the stream open, allowing unauthenticated messages to reach the backend microservice.
**`grep_search`:** `stream`, `BidiStreaming`.

---

## 🛡️ Fix

1. **Disable Reflection:** Never use `reflection.Register(s)` in production code. Use environmental flags.
2. **Channel Security:** Always use `grpc.credentials.createSsl()` or rely on strict service mesh mTLS policies.
3. **Payload Limits:** Configure `MAX_RECEIVE_MESSAGE_LENGTH`.
4. **Proxy Config:** Ensure ingress gateways use native `grpc_pass` (HTTP/2 end-to-end) and do not downgrade to HTTP/1.1.

---

## 📌 References
- [[mobile-api-security-surface]]
- [gRPC Security Standards](https://grpc.io/docs/guides/auth/)
