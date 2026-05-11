# XTEAther

A preservation tool for the Steam release of Dead Space 2.

## Disclaimer

The Steam release of Dead Space 2 uses TAGES Solidshield, a legacy DRM that limits the game to five authorized PCs. If you no longer have access to those machines to deauthorize them, any attempt to activate on a new machine fails with "The activation limit has been exceeded," and EA Support has indicated they can no longer reset this limit.
 
XTEAther helps owners of the Steam release play the game they paid for when they're locked out. The user still needs to own the game on Steam for any of this to be useful.

Background: [Dead Space 2 activation limit lockout](https://consumerrights.wiki/w/Dead_Space_2_activation_limit_lockout).

## What it does

1. Decrypts the encrypted code sections. The DRM stub does this at runtime using XTEA in OFB mode.
2. Restores the original instructions for functions that were virtualized into the DRM's VM.
3. Strips the DRM sections from the PE.
4. Rewrites the PE header to skip the DRM entry point.

The result is a clean executable that runs without ever calling into the DRM or asking for activation.

## Supported build
 
The Steam build only.

## Usage


```
XTEAther.exe path\to\deadspace2.exe
```

Download: [version requiring .NET 10](https://github.com/Wemino/XTEAther/releases/latest/download/XTEAther.zip) or [standalone version](https://github.com/Wemino/XTEAther/releases/latest/download/XTEAther-standalone.zip).

The original file is renamed to `deadspace2.exe.bak` and a clean executable is written in its place.
