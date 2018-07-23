CXX = g++
CXXFLAGS = -O2
INCPATH = -I

LINK = g++
LFLAGS = 
# LIBS = -L/usr/lib/i386-linux-gnu -lpthread
LIBS = -lpthread -I/usr/local/ssl/include/ -lssl -lcrypto  -ldl -L/usr/local/ssl/lib

INSTALL_FILE = install -m 777 -p

objects :=$(wildcard *.cpp)
objects +=$(wildcard *.c)

cur_dir := $(shell pwd) 
host_name := $(shell whoami)
host_type := $(shell arch)

#模式规则
# %.o: %.cpp %.c
# 	$(CXX) -c $(CXXFLAGS) -o $@ $<

.PHONY: all clean

all = RTSP

$(all): $(objects)
	@echo $(objects)
	$(LINK) $(LFLAGS) -o $@ $^ $(LIBS)

clean:
	-rm -f $(all) *.d *.o

install:
	-$(INSTALL_FILE) RTSP ~/Desktop
