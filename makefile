obj = dnsfilter.o udpcheck.o dns_analyze.o dns_modify.o

dnsfilter : $(obj)
	gcc -o dnsfilter $(obj) -lnetfilter_queue -lpthread

dnsfilter.o : udpcheck.h dns_analyze.h
udpcheck.o : udpcheck.h
dns_analyze.o : dns_analyze.h
dns_modify.o : dns_modify.h

clean :
	rm -f dnsfilter $(obj)
