## SLC (Socket Lost Control)

```
git clone https://github.com/ammarfaizi2/slc;

cd slc;

apt install clang -y;

clang++ -Wall -Wextra -O3 slc.cpp -o slc -lpthread;
```

### Usage

```
Usage:
	./slc server [circuit_addr] [circuit_port] [public_addr] [public_port]
	./slc client [target_addr] [target_port] [circuit_addr] [circuit_port]
```

### Example

```bash
  ./slc client 127.0.0.1 5555 123.123.123.123 9999
  ./slc server 123.123.123.123 9999 0.0.0.0 9998
```

## License
This repo is licensed under [GPL-2.0](LICENSE) license.
