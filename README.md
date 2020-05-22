# PRX.ENC-Tool
As the name implies this project allows the decryption or encryption of PRX.ENC files from Sony JIG Memory sticks

Modify unsigned char ms_id[] accordingly, to dump the MS ID Please use https://github.com/mathieulh/Dump-MemoryStick-ID 

The MSID is stored at 0x1E0 in the dump (attr0.bin file)

Decrypting the JIG OS2 file often found on JIG memory sticks requires the use of https://github.com/mathieulh/JIG-OS2-Tool

The PSP folder contains a version meant to run on PSP, the PC folder contains a version of this tool meant to run on PC.

PSP Application developped by Mathieulh (all Credits go to the M33 Team)

PC Version ported by Zecoxao.

The PSP version DOES NOT support encryption.
