---
categories:
    - hardware
    - pwnagatchi
layout: post
title: Pwnagatchi Setup Guide
image: 
tags:
    - hardware
    - iot
---

## Introduction

Pwnagatchi is a small, portable device designed for wifi penetration testing. It's perfect as an security enthusiast tool looking to learn about wifi password security and a cheaper alternative to some of the features of devices such as the flipper zero. This guide aims to help people stuck on setting it up like I was due to the transition from official support to community support.

I initially used [official documentation](https://pwnagotchi.ai/) as the reference documentation for the setup but soon realized that it was outdated and no longer maintained. I figured it out when the display I had ordered was 2 versions higher and it was no longer supported by the official guide. Following the [community guide](https://pwnagotchi.org), I managed to get my Pwnagatchi working perfectly and it is pretty much straightforward/

## Hardware Setup

### Components Needed:
- Raspberry Pi Zero W
- MicroSD Card (at least 8GB recommended)
- USB-C Cable
- Power Bank or USB-C Adapter / Battery Mod
- Display - Waveshare eInk 2.13 inch
- Case (optional)

### Assembly:

- The display is straightforward to connect, just allign the pins and press down firmly.
- I used the powerbank as the power source but there is a battery mod which would make the Pi zero more portable. It requires soldering skills though.
- There are designs available to 3D print your own case. I did not own one so I made mine using glue and some cardboard lol.
- I ordered the pins already soldered into my raspberry pi zero w.


## Installation Steps

- connect the SDCard to a computer and flash it using the [raspberry pi imager](https://www.raspberrypi.com/software/) with the download [image](https://github.com/jayofelony/pwnagotchi/releases) from github. 
- Once the image is flashed, Navigate to it and there should be two directories created `boot` and `rootfs`
- In the `rootfs` you can create a `config.toml` file with the name, display type and other configuration options.
- Setup SSH by following the community guide and further fine tune your pwnagotchi setup.

## Conclusion

I had a lot of fun building this project. It was a great way to learn more about raspberry pi zero w and its capabilities. I also collected some wifi hashes and cracked it with my machine. It's definitely a fun project for anyone interested in cybersecurity and hardware hacking.
I will definitely be working on more projects like this in the future.

## References

- [Pwnagotchi GitHub](https://github.com/jayofelony/pwnagotchi)
- [Raspberry Pi Imager](https://www.raspberrypi.com/software/)