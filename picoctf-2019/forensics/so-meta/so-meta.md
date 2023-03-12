# So Meta

## Problem Description

Find the flag in this [picture](https://jupiter.challenges.picoctf.org/static/916b07b4c87062c165ace1d3d31ef655/pico_img.png).

| Points  | Category   | Author     |
| ------- | ---------- | ---------- |
| 150     | Forensics  | Stephen Xu |

### Writeup

The hint of this challenge tells us to look at the metadata of the file. Metadata in a file is data that tells us more about the file. For example, metadata of an image may include the image size, such as 1920x1080.

The file we are given is a picture, which is a png file called `pico_img.png`. To view metadata of image files, we can use a tool called [exiftool](https://exiftool.org/). Running the command, we receive the following output.

```BASH
$ exiftool pico_img.png
ExifTool Version Number         : 12.42
File Name                       : pico_img.png
Directory                       : .
File Size                       : 109 kB
File Modification Date/Time     : 2020:10:26 11:38:23-07:00
File Access Date/Time           : 2023:03:11 17:09:57-08:00
File Inode Change Date/Time     : 2023:03:11 17:09:49-08:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 600
Image Height                    : 600
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
...
PNG IDAT (may be ignored by some readers)
Artist                          : picoCTF{s0_m3ta_d8944929}
Image Size                      : 600x600
Megapixels                      : 0.360
```

Under the metadata describing the artist of the image, we receive the flag.

```FLAG
picoCTF{s0_m3ta_d8944929}
```
