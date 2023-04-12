# e-go-BPF

Ever wanted bpf-like capabilities for your go program? Well, look no further than me! I have a big ego! I am egoBPF!

## Installation/Usage

### gccgo

1. Install `gccgo`

```console
$ sudo dnf install gccgo
```

2. Use `-pg -mfentry -mnop-mcount -mrecord-mcount`
