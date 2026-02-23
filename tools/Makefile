CC = gcc

DEBUG_ARGS   = -g -D DEBUG
RELEASE_ARGS = -Wall -Wextra -Wpedantic -Wformat=2 -Wcast-qual -Wcast-align \
				-Wconversion -Wsign-conversion -Wshadow -Wpointer-arith \
				-Wstringop-overflow \
				-Wswitch-enum -Wundef -Wuninitialized -Wdouble-promotion \
				-Wnull-dereference -Walloc-zero -Walloca -Wvla \
				-Werror -O2 -march=native -s \

SOURCES_HCX_POTFILE = src/hcx-potfile.c src/utils.c
SOURCES_HCX_INFO = src/hcx-info.c src/utils.c
SOURCES_HCX_STATUS = src/hcx-status.c src/utils.c
OUT_HCX_INFO = hcx-info
OUT_HCX_POTFILE = hcx-potfile
OUT_HCX_STATUS = hcx-status

debug:
	$(CC) $(DEBUG_ARGS) $(SOURCES_HCX_INFO)    $(CFLAGS) -o $(OUT_HCX_INFO)
	$(CC) $(DEBUG_ARGS) $(SOURCES_HCX_POTFILE) $(CFLAGS) -o $(OUT_HCX_POTFILE)
	$(CC) $(DEBUG_ARGS) $(SOURCES_HCX_STATUS)  $(CFLAGS) -o $(OUT_HCX_STATUS)

release:
	$(CC) $(RELEASE_ARGS) $(SOURCES_HCX_INFO)    $(CFLAGS) -o $(OUT_HCX_INFO)
	$(CC) $(RELEASE_ARGS) $(SOURCES_HCX_POTFILE) $(CFLAGS) -o $(OUT_HCX_POTFILE)
	$(CC) $(RELEASE_ARGS) $(SOURCES_HCX_STATUS)  $(CFLAGS) -o $(OUT_HCX_STATUS)

install:
	sudo ln -sfr hcx-info /usr/local/bin/.
	sudo ln -sfr hcx-potfile /usr/local/bin/.
	sudo ln -sfr hcx-status /usr/local/bin/.

clean:
	rm hcx-info
	rm hcx-potfile
	rm hcx-status
