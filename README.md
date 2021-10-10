> # __A fast, quick, and easy to use network scanner__

_a couple days ago, I have decided to scan my school network, i had to wait a really long time for nmap to finish and also it didnt even discover hosts that blocked IMCP, mission failed._


That was the problem that started this project, my idea was to create a fast network discovery tool with the ability to do it fast and with just one command, and thats what i managed to make.

Now, you're probably thinking: __and why the fuck should i use this when i have nmap?__.

Well, nmap is a great tool for port scanning and extensive enumeration, but speed and host discovery aren't it's main points.

So, let's recap:

Nmap is a better option when:
  - You need to do enumeration.
  - Speed isn't an esential feature.

And Scanz, in the other hand, is a better option when:
  - You need to discover hosts on a network
  - Speed is a needed feature


---
---
> # _Installation:_
Download the correct release for your OS from the releases tab and just run the executable

```bash
./scanz
```

---
---

> # __Usage:__
If you run the script without supplying any arguments, you will be promted to the help page:

```bash
A fast and powerful ARP based network scanner

positional arguments:
  target                the network interface or the ip the program is going to use

optional arguments:
  -h, --help                          show this help message and exit
  --use_ip                            specifies to the target that an ip will be used
  --timeout seconds                   scan response timeout, defaults to 2 seconds
  --process_threads process_threads   how many threads run in each processs, defaults to 256
  --process_num process_number        how many process run, defaults to 20
  --output filename                   where to save the output, wont save if not specified
  --subnets levels                    how many subnet levels scan, defaults to one

```

Lets go trough some arguments and explain exactly what it does:

- _target:_ It will fetch the ip from the provided interface name by default. For example, if the target ip is 192.168.0.1, it will scan 192.168.0.0/24

- _subnets:_ how many subnets levels scan, for example if the subnetting level is 1 (default) and the ip 192.168.0.1, it will scan 192.168.0.0-255, while if the subnet level is 2 it will scan 192.168.0-255.0-255

- _timeout:_ how much will the program wait until the ip answers before it timeouts

- _output:_ where to save the output of the program, if not specified, it wont save

- _use_ip:_ if specified, it will treat the target as an ip and not an interface name
---
---

> # __Future features:__

## _possible features:_

- ~~make the program more portable, for example, just download the python script and run it~~ Done! 🎉

- ~~make it possible for the program to run without needing root, making it posible to be ran on un-rooted targets~~ imposible by the nature of the scanner

- ~~faster scan times, specially on multiple subnetts~~ Done! 🎉

- create a good documentation for the script and cofigure push requests so people can create a better code

- make the scanner run on windows

- ~~let the scanner take an ip address instead of an interface name, specially for windows targets~~ Done! 🎉

---
---

> # __Future development__

This started as a side project and not something to actively maintain, i just made a pretty useful tool and i wanted to share it with the world and maybe help a couple people._I will try to work as hard as i can to fix the bugs you find and add the promised features, i never hosted a public git project as big as this before_. Im not gonna <!-- give you up, never gonna let you down --> be able to be online for a couple weeks as my school final exams are coming.

I would love to hear your feedback at fva#1693 on discord, just send me a friend request and i will probably accept it!

WOW. did you read all the way down here? well, congrats! I leaved some fun stuff hidden on the raw markdown, bye!
