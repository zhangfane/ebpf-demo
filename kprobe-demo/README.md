## Usage

In order to install the kenrel module use the following steps:

Step 1 - compile the kernel module object file.
```
make
```

Step 2 - Install the kernel module into the kernel.

```
make install
```

Step 3 - Observe the logs printed by the module.

```
sudo dmesg -w
```

To uninstall the module please use the following command:

``` bash
make uninstall
```
