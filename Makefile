all: pcap-test

pcap-test: main.o pkt_handler.o
	g++ -o pcap-test main.o pkt_handler.o -lpcap

pkt_handler.o: pkt_handler.cpp pkt_handler.h
	g++ -c -o pkt_handler.o pkt_handler.cpp

main.o: main.cpp pkt_handler.h
	g++ -c -o main.o main.cpp

clean:
	rm -f pcap-test *.o