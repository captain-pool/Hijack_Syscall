# Hijacking System Call Table using Linux Kernel Module

Demo application for GNX LinuxFest 2019

Usage
---------
### Compiling the module
`$ make all`

### To Use
`$ sudo insmod ovropen.ko filename=laugh.mp3 target_extension=.mp3`

### To Remove
`$ sudo rmmod ovropen`

Executing any mp3 file will result in playing of laugh.mp3.
