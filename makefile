toxcore:
ifneq ($(wildcard ../toxcore/.*),)
	cd ../toxcore && autoreconf -i && ./configure && make && make install
else
	cd ../ && git clone https://github.com/pirebok/toxcore.git && cd toxcore && autoreconf -i && ./configure --prefix=/usr && make && make install
endif


test:
	gcc test.c -o test-piling -lsodium -ltoxcore

