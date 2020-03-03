# Ethernet Sniffer

The following workshop script works like a `packet sniffer` where it prints the whole components of the requested network packets on your local machine. Internally evaluates and splits all the components from the `IP`, `TCP` and the `UDP` stacks, passing before through the `Ethernet layer` and its details as well.

This sniffer is a RAW socket configuration and uses the `htons` functions that help on the conversion of integer types from `host byte order` to `network byte order`. Basically this will run like an analyzer of all the packets received, split them in fields w/o using any third-party library and show its details

# Ethernet, IP TCP and UDP

Cover and explain every part of each involved network stack is way too large. These concepts are the main foundations of how we consume the internet and how each network bit is transferred. You can check and research for every layer diagram for more information.

# Usage

This script uses Python built-in modules, but if you want you can use a `virtualenv` setup. After that, you will need to run the `sniffer.py` and that's it.

For extracting certain elements, a little bit of bit-wise operations such as Left Shift and AND (&) operators were necessary.

## Credits

 - [David E Lares](https://twitter.com/davidlares3)

## License

 - [MIT](https://opensource.org/licenses/MIT)
