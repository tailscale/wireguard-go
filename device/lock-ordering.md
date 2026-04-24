# Lock Ordering in wireguard-go/device

## Lock hierarchy

Locks must be acquired in the order listed below. A goroutine holding a
lock with a higher number must never attempt to acquire a lock with a
lower number.

```
Level 0  device.state.Mutex
Level 1  device.ipcMutex                  (sync.RWMutex)
Level 2  device.net.RWMutex
Level 3  device.staticIdentity.RWMutex
Level 4  device.peers.RWMutex
Level 5  peer.state.Mutex
Level 6  peer.handshake.mutex             (sync.RWMutex)
Level 7  peer.keypairs.RWMutex
Level 8  device.allowedips.mu             (sync.RWMutex)
Level 9  device.indexTable.RWMutex
Level 10 peer.endpoint.Mutex
Level 11 device.cookieChecker.RWMutex
Level 12 peer.cookieGenerator.RWMutex
Level 13 Timer.modifyingLock / Timer.runningLock
```

Not every pair of locks appears in practice; the ordering above is the
transitive closure of the pairs that do.
