all: pcap-test

pcap-test: pcap-test.o
	g++ -o pcap-test pcap-test.o -lpcap

pcap-test.o: pcap-test.c
	g++ -c -o pcap-test.o pcap-test.c

clean:
	rm -f pcap-test *.o