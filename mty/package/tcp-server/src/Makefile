GCC_PATH=/opt/trunk/1505/SDK/staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_musl-1.1.11/bin

tcp-server : tcp-server.o
	$(GCC_PATH)/mips-openwrt-linux-gcc $(LDFLAGS) tcp-server.o -o tcp-server

tcp-server.o : tcp-server.c
	$(GCC_PATH)/mips-openwrt-linux-gcc $(CFLAGS) -c tcp-server.c

clean :
	rm *.o tcp-server
