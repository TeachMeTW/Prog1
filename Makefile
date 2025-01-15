# Makefile

CXX = g++
CC  = gcc

CXXFLAGS = -Wall -Wextra -g
CFLAGS   = -Wall -Wextra -g
LDFLAGS  = -lpcap

OBJS = trace.o checksum.o

TARGET = trace

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

trace.o: trace.cpp EthernetHeader.h ARPHeader.h IPHeader.h ICMPHeader.h TCPHeader.h UDPHeader.h checksum.h
	$(CXX) $(CXXFLAGS) -c trace.cpp

checksum.o: checksum.c checksum.h
	$(CC) $(CFLAGS) -c checksum.c

clean:
	rm -f $(OBJS) $(TARGET)
