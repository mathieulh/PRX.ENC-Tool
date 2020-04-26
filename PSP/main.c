#include <pspsdk.h>
#include <pspkernel.h>
#include <psputilsforkernel.h>
#include <pspcrypt.h>
#include <pspctrl.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <malloc.h>

PSP_MODULE_INFO("DecryptSP", 0x1000, 1, 0);
PSP_MAIN_THREAD_ATTR(0);

#define printf pspDebugScreenPrintf

u8 buffer[10000000] __attribute__((aligned(64)));


void ErrorExit(int milisecs, char *fmt, ...)
{
	va_list list;
	char msg[256];	

	va_start(list, fmt);
	vsprintf(msg, fmt, list);
	va_end(list);

	printf(msg);

	sceKernelDelayThread(milisecs*1000);
	sceKernelExitGame();
}

int ReadFile(char *file, void *buf, int size)
{
	SceUID fd = sceIoOpen(file, PSP_O_RDONLY, 0);
	if (fd < 0)
		return fd;

	int read = sceIoRead(fd, buf, size);
	sceIoClose(fd);

	return read;
}

int WriteFile(char *file, void *buf, int size)
{
	SceUID fd = sceIoOpen(file, PSP_O_WRONLY | PSP_O_CREAT | PSP_O_TRUNC, 0777);
	if (fd < 0)
		return fd;

	int written = sceIoWrite(fd, buf, size);
	sceIoClose(fd);

	return written;
}

int Kirk(void *inbuf, void *outbuf, int func)
{
	//printf("Calling semaphore...\n");
	
	int res = semaphore_4C537C72(inbuf, 3000000, outbuf, 3000000, func);
	
	//printf("Semaphore res: %08X.\n", res);
		
	return res;
}

u8 header_p1[0xb0];
u8 header_p2[0x80];

//file_head len 0x4
char file_head[] = {0,0,0,0};
 
//msp_id len 0x10
 
u8 ms_id[] = {
    0x20, 0x4D, 0x53, 0x50, 
	0x53, 0x4E, 0x59, 0x30, 
	0x00, 0x79, 0x20, 0x01, 
	0x1A, 0xD5, 0x00, 0x00
};
 
u8 key0[112] = 
{
	0x39, 0x81, 0xE2, 0x63, 0x96, 0xF5, 0x0D, 0x48, 0xDB, 0xCF, 0x76, 0xCF, 0x91, 0x9F, 0xF6, 0xF1, 
	0x13, 0x11, 0xF9, 0x0A, 0xB7, 0x87, 0x2E, 0x4C, 0xC9, 0x14, 0x03, 0xC4, 0x11, 0x4E, 0x38, 0xF8, 
	0x96, 0xD4, 0x56, 0x68, 0x9D, 0xB0, 0x61, 0x9C, 0x81, 0xCF, 0xB3, 0x4B, 0x7D, 0xDC, 0xF1, 0x75, 
	0xDF, 0x4D, 0x5A, 0x9F, 0x00, 0x76, 0xAD, 0x54, 0x5E, 0x5E, 0x40, 0x28, 0xDF, 0x36, 0x38, 0x17, 
	0x23, 0x28, 0x80, 0x08, 0x00, 0x82, 0xDD, 0xF2, 0x5F, 0xCC, 0x45, 0x9A, 0x9B, 0x9D, 0x83, 0x07, 
	0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 
	0x47, 0xA3, 0x62, 0xA8, 0x5B, 0xBD, 0xA1, 0x8D, 0xFB, 0xCA, 0xF4, 0xD2, 0xFC, 0xE6, 0xC8, 0x31
};

unsigned char rawData[16] =
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x56, 0x01, 0x00, 0x10, 0x81, 0xFF, 0xFF, 0x01, 0x28, 
} ;



u8 dummy[0x80]; 


int Decrypt(u8* buf, int size, u8* msp_id, int unk2, int* out_size)
{
	int enc_size, ret, i, delta;
	u8 *start_ptr;
	u32 *buf32 = (u32 *)buf;
	
	enc_size = buf[0xb3]<<24 | buf[0xb2]<<16 | buf[0xb1]<<8 | buf[0xb0];
	*out_size = enc_size;
 
	if ((size-0x150) < enc_size) return -0xCD;

	//===================================================================================
	//stage 1
	//===================================================================================
	memcpy(header_p1, buf, 0xb0);
 
	ret = Kirk(buf, buf, 0xF);
	if (ret != 0) return -0x65;
 
	//===================================================================================
	//stage 2
	//===================================================================================
 
	buf32[0] = 4; // 0
	buf32[1] = 0; // 4
	buf32[2] = 0; // 8
	buf32[3] = 1; // C
	buf32[4] = 0x80; // 0x10
	start_ptr = buf;
 
	memcpy(buf+0x14, msp_id, 0x10);
	memcpy(buf+0x24, key0, 0x70);
 
	ret = Kirk(buf, buf, 0x4);
	if (ret != 0) return -0x66;

	//===================================================================================
	//stage 3
	//===================================================================================
 
	memcpy(header_p2, buf+0x14, 0x80);
 
	u32 *addr = (u32 *)start_ptr;
	*(addr) = 0xAC;
 
	memcpy(buf+0x4, header_p2+0x6c, 0x14);
	memcpy(buf+0x18, header_p1+0x18, 0x80);
 
	ret = Kirk(buf, buf, 0xB);
	if (ret != 0) return -0x67;
 
	//===================================================================================
	//stage 4
	//===================================================================================
	u8 *hdr_p1_offset = header_p1+0x4;
	//WriteFile("ms0:/hdr_p1_offset.bin", hdr_p1_offset, 0x14);
	//WriteFile("ms0:/buf.bin", buf, 0x40);
	for(i = 0; i < 0x14; i++)
	{
		if (hdr_p1_offset[i] != buf[i])
		{	
			delta = hdr_p1_offset[i] - buf[i]; 
			return -0x12e;
		}
	}
 
	buf32[6] = 5; // 0x18
	buf32[7] = 0; // 0x1C
	buf32[8] = 0; // 0x20
	buf32[9] = 0x41; // 0x24
	buf32[10] = 0x80; // 0x28
	start_ptr = buf+0x18;
 
	memcpy(buf+0x2c, header_p1+0x30, 0x80);
 
	ret = Kirk(buf+0x18, buf+0x18, 0x7);
	if (ret != 0) return -0x68;
 
	//===================================================================================
	//stage 5
	//===================================================================================
	u8 *tmp_ptr = buf+0x18;
	for(i = 0; i < 0x80; i++)
	{
		tmp_ptr[i] = tmp_ptr[i] ^ header_p2[i];
	}
 
	buf32[1] = 5; // 4
	buf32[2] = 0; // 8
	buf32[3] = 0; // C
	buf32[4] = 0x41; // 0x10
	buf32[5] = 0x80; // 0x14
	start_ptr = buf+0x4;
 
	ret = Kirk(buf+0x4, buf+0x4, 0x7);
	if (ret != 0) return -0x69;
 
	//===================================================================================
	//stage 6
	//===================================================================================
	tmp_ptr = buf+0x14;
	//WriteFile("ms0:/tmp_ptr.bin", tmp_ptr, 0x40);
	//WriteFile("ms0:/msp_id.bin", msp_id, 0x10);
	for (i = 0; i < 0x10; i++)
	{
		if (tmp_ptr[i] != msp_id[i])
		{
			delta = tmp_ptr[i] - msp_id[i];
			return -0x12f;
		}
	} 
	
	//WriteFile("ms0:/buf_pre_memcpy.bin", buf, 0x300);
 
	//memcpy(buf+0x30, buf+0x4, 0x80);
	for (i = 0x7F; i >= 0; i--)
	{
		buf[0x30+i] = buf[0x4+i];
	}

	memcpy(buf+0x40, buf+0x30, 0x10);
	memcpy(unk2, buf+0xd0, 0x80);

	//WriteFile("ms0:/buf_pre_kirk.bin", buf, 0x300);
 
	ret = Kirk(buf, buf+0x40, 1); // ??? should not be r16?
	if (ret != 0) return -0x130;
 
	return 0;
}

int DecryptFile(char *input, char *output)
{
	printf("Decrypting %s to %s.\n", input, output);
	
	int outsize;
	int size = ReadFile(input, buffer, sizeof(buffer));

	if (size < 0)
	{
		printf("Error: cannot read %s.\n", input);
		return -1;
	}

	int res = Decrypt(buffer, size, ms_id, dummy, &outsize);

	if (res != 0)
	{
		printf("Error decrypting %s.\n", input);
		return -1;
	}

	if (WriteFile(output, buffer, outsize) != outsize)
	{
		printf("Error writing/creating %s.\n", output);
		return -1;
	}

	return 0;
}

char *tolower(char *s)
{
	int i;

	for (i = 0; i < strlen(s); i++)
	{
		if (s[i] >= 'A' && s[i] <= 'Z')
			s[i] += 0x20;
	}

	return s;
}

char input[128], output[128];

void DecryptDir(char *indir, char *outdir)
{
	SceUID dfd = sceIoDopen(indir);	

	if (dfd >= 0)
	{
		SceIoDirent dirent;

		memset(&dirent, 0, sizeof(SceIoDirent));
		
		while (sceIoDread(dfd, &dirent) > 0)
		{
			sprintf(input, "%s/%s", indir, dirent.d_name);
			sprintf(output, "%s/%s", outdir, dirent.d_name);

			output[strlen(output)-4] = 0; // remove enc extension

			if (dirent.d_name[0] != '.')
			{
				
				
				if (DecryptFile(input, output) != 0)
					sceKernelDelayThread(800000);
				else
					sceKernelDelayThread(150000);
			}
		}

		sceIoDclose(dfd);
	}
}


int main()
{	
	int outsize;
	
	pspDebugScreenInit();

	sceIoMkdir("ms0:/dec", 0777);
	DecryptDir("ms0:/prx", "ms0:/dec");


	ErrorExit(10000, "Done.\n");

	return 0;
}
