# can2eth-kernel-module
The `can2eth-kernel-module` allows for transferring CAN frames over IP networks, similar to userland tools like [socketcand](https://github.com/linux-can/socketcand) or [cannelloni](https://github.com/mguentner/cannelloni).

## Overview
The idea behind the project is that dissecto GmbH has developed a hardware device that can be connected to a CAN bus and acts as an ethernet gateway to the bus. It is capable of capturing the CAN traffic along with the corresponding timestamps and send this data via UDP or it can receive CAN frames via UDP as well and pass them on to the CAN bus.
This allows for remote interaction with a CAN bus, as well as an accurate analyses of CAN traffic, as packets contain precise timestamps.

Features:
- Communication via UDP
- Frame aggregation in UDP frames (multiple CAN frames in one UDP frame)
- Both CAN and CAN FD support
- Allows multiple CAN over IP tunnels simultaneously (default is two)


## Requirements
The module requires certain functions provided by can_dev. Therfore it has to be loaded **before** inserting the *canToEthMod*-Module. <br>
```
modprobe can_dev
```

## Loading the module
The default configuration of the module can be loaded by running
```
insmod canToEthMod.ko
```

## Configuring the module
The module has three configurable parameters, which can be set when loading the module:

1. **port** <br>
   The UDP port the module listens to on the host machine. <br>
   **Default:** 8765

2. **ip_addrs** <br>
   A list of up to 10 IP addresses to which CAN frames received from the CAN interfaces of the module are sent.
   - If no addresses are specified, the default is `0.0.0.0:port`.
   - Addresses should be in the form: `ip4_address:port` and are separated by commas.

3. **timeout_ns** <br>
   The timeout the module uses for frame aggregation (in nanoseconds). <br>
   **Default:** 10000000

### Examples
To configure the module to listen to port 1234 and use a 1s timeout for the frame aggreggation one would run
```
insmod canToEthMod.ko port=1234 timeout_ns=1000000000
```

To configure the IP adress 10.0.0.6 and port 4321 as a destination adress run
```
insmod canToEthMod.ko ip_addrs="10.0.0.6:4321"
```

To send to both 10.0.0.6 at port 4321 and 10.0.0.7 at port 8765 run
```
insmod canToEthMod.ko ip_addrs="10.0.0.6:4321,10.0.0.7:8765"
```

## Creating a Tunnel
In order to create a tunnel between two hosts *A* and *B*, the module has to be running on each of them with the other host set as the destination host.

### Example
Suppose host *A* has the IP address `10.0.0.5` and starts the module listening on port `8765`. Host *B* has the IP address `10.0.0.6` and listens on port `4321`.

Configuration Host *A*:
```
insmod canToEthMod.ko port=8765 ip_addrs="10.0.0.6:4321"
```

Configuration Host *B*:
```
insmod canToEthMod.ko port=4321 ip_addrs="10.0.0.5:8765"
```

The module will now open two CAN interfaces on host *A* (e.g., `can0` and `can1`), which correspond to the two CAN interfaces opened by the module on host *B*. CAN frames appearing on `can0` on host *A* will be sent to host *B* and displayed on the equivalent CAN interface, keeping the timestamps from when they appeared on the interface on host *A*.

This approach is not limited to just two devices. However, there is currently no autoconfiguration between the modules on different hosts, meaning each module opens two interfaces and identifies them as interface 0 and interface 1.

## The Protocol
Each UDP frame contains multiple CAN frames.

The header of a UDP frame contains the following information:
| Bytes | Name      | Description |
|-------|-----------|-------------|
|   4   | magic     | Magic number ("C2EG") |
|   8   | Timestamp | Timestamp in c `struct timespec` format:<br>- First 4 bytes: seconds since boot, big-endian<br>- Second 4 bytes: nanoseconds in this second (0-1000000000), big-endian |
|   2   | seqno   | Sequence number; big-endian |
|   2   | size      | Message size in bytes; big-endian |

After the header, the data follows.
There are three kinds of data chunks that can appear in the data section:
1. "normal" CAN frames - 0xc0fe
2. keep alive frames - 0x57a7
3. error frames - 0xfa11

Each chunk is prefixed by its type and size,
| Bytes | Name      | Description |
|-------|-----------|-------------|
|   2   | Chunk Size | Chunk size, excluding the size for this and chunk type |
|   2   | Chunk Type | Type, see above |

followed by it's actual data
| Bytes | Name      | Description |
|-------|-----------|-------------|
|   8   | Timestamp | Timestamp in c `struct timespec` format:<br>- First 4 bytes: seconds since boot, big-endian<br>- Second 4 bytes: nanoseconds in this second (0-1000000000), big-endian |
|   4   | can_id | CAN ID + EFF/RTR/ERR flags, see `<linux/can.h>` |
|   1   | interface_idx | interface identifier |
|   1   | reserved | reserved for future use |
|   1   | len | size of the CAN payload |
|   1   | flags | CAN FD flags  |
| 0 - 64 | data | CAN data section |