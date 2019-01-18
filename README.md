 gcfc32 - PE32 inter-sections gapes cleaner & filler console utility ver. 1.0.0.1

 Command line:
  gcfc32 <PE32File.ext> [Options]

 Options:

 -V(erbose) - verbose output<br/>
 -C(lean) - clean gapes between sections (default filler is 0x00)<br/>
 -F(iller):Value - set user defined filler value (byte)<br/>
 -S(um) - calculate PE image checksum

 Simple console utility application can be used to view content of PE32 inter-sections gapes or to fill them with specified or default filler.

 Use makefile to build executable file. Adjust variables with valid pathes.


