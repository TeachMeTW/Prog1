# Makefile

CXX = g++
CC  = gcc

CXXFLAGS = -Wall -Wextra -g
CFLAGS   = -Wall -Wextra -g
LDFLAGS  = -lpcap

OBJS = trace.o checksum.o

TARGET = trace

# Detect OS and set the source file for trace accordingly
ifeq ($(shell uname -s),Darwin)
    TRACE_SRC = trace_mac.cpp
else
    TRACE_SRC = trace_linux.cpp
endif

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

# Compile trace.o from the appropriate source based on OS
trace.o: $(TRACE_SRC) EthernetHeader.h ARPHeader.h IPHeader.h ICMPHeader.h TCPHeader.h UDPHeader.h checksum.h
	$(CXX) $(CXXFLAGS) -c $(TRACE_SRC) -o trace.o

checksum.o: checksum.c checksum.h
	$(CC) $(CFLAGS) -c checksum.c

clean:
	rm -f $(OBJS) $(TARGET)
