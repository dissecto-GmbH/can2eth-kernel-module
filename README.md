# can2eth-kernel-module

## Requirements
The module requires certain functions provided by can_dev. Therfore it has to be loaded **before** inserting the *canToEthMod*-Module. <br>
```
sudo modprobe can_dev
```

