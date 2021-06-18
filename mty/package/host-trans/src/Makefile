GCC_PATH=/opt/trunk/1505/SDK/staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_musl-1.1.11/bin
LDFLAGS+=-lz

host-trans : host-trans.o
	$(GCC_PATH)/mips-openwrt-linux-gcc $(LDFLAGS) -o $@ host-trans.o

host-trans.o : host-trans.c host-trans.h
	$(GCC_PATH)/mips-openwrt-linux-gcc $(CFLAGS) -c host-trans.c

clean :
	rm *.o host-trans
