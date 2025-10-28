## Ethernet Sniffer

The following workshop script works like a `packet sniffer` where it prints the whole components of the requested network packets on your local machine. Internally evaluates and splits all the components from the `IP`, `TCP`, and `UDP` stacks, passing through the `Ethernet layer` and its details as well.

This sniffer is a RAW socket configuration and uses the `htons` functions that help with the conversion of integer types from `host byte order` to `network byte order`. Basically, this will run like an analyzer of all the packets received, split them into fields w/o using any third-party library, and show their details

# Ethernet, IP, TCP, and UDP

Cover and explain every part of each involved network stack is way too large. These concepts are the main foundations of how we consume the internet and how each network bit is transferred. You can check and research every layer diagram for more information.

# Usage

This script uses Python built-in modules, but if you want, you can use a `virtualenv` setup. After that, you will need to run the `sniffer.py` and that's it.

For extracting certain elements, a little bit of bit-wise operation,s such as Left Shift and AND (&) operators, was necessary.

## Credits
[David Lares S](https://davidlares.com)

## License
[MIT](https://opensource.org/licenses/MIT)
