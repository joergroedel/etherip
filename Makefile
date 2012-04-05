ethiptunnel: ethiptunnel.c
	$(CC) -O3 -o ethiptunnel ethiptunnel.c

driver:
	$(MAKE) -C driver

driver-install:
	$(MAKE) -C driver install

install:
	mkdir -p $(DESTDIR)/usr/sbin
	cp ethiptunnel $(DESTDIR)/usr/sbin/

clean:
	@rm -f ethiptunnel
	$(MAKE) -C driver clean

.PHONY: clean driver driver-install install
