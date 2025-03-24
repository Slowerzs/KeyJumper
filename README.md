# KeyJumper

This project demonstrates arbitrary kernel code execution on a Windows 11 system with kCET enabled, to create a keylogging tool by mapping kernel memory to userland.

You can find my blogpost about it [here](https://blog.slowerzs.net/posts/keyjumper/) for more information.


## Compilation

This project uses the Meson build system, and is written in `C23`. MSVC does not yet support `C23` (I think?), so I suggest using `clang-cl` as a compiler.

Setup the `CC` and `LD` environment variables (`clang-cl` and `lld-link` if using the LLVM tooclhain), then:
```
meson setup builddir
meson compile -C builddir
```

## Windows version

This project uses hardcoded offsets, that were taken on a Windows 11 22H2, build version `22261.4890`. To target another version, updating the offsets is required.
All the offsets of the gadgets used are located within `include/jop/offsets.h`.

While not all gadgets have exact equivalents on other version, the central elements do, and others have remplacements (`pop rax ; ... ; jmp XXX`, `call XXX ; ... ; jmp XXX`).

## Credits

- [rp++](https://github.com/0vercl0k/rp) ([Axel Souchet](https://x.com/0vercl0k)) - A great tool to search for gadgets
- [KexecDDPlus](https://github.com/scrt/KexecDDPlus?tab=readme-ov-file) ([Clément Labro](https://infosec.exchange/@itm4n) / [Romain Melchiorre](https://infosec.exchange/@pmain)) and [KexecDD](https://github.com/floesen/KExecDD) ([floesen_](https://x.com/floesen_)) - The original admin-to-kernel arbitrary call primitive
- [This Windows 10 keylogging implementation](https://eversinc33.com/posts/kernel-mode-keylogging.html) ([eversinc33](https://x.com/eversinc33)) and [the original presentation of the technique](https://i.blackhat.com/BH-US-23/Presentations/US-23-Palmiotti-Boonen-Close-Encounters.pdf) ([chompie](https://x.com/chompie1337) / [b33f](https://x.com/FuzzySec))