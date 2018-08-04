CXX = g++
CXXFLAGS = -O2
INCPATH = -I

DIR_SRC = ./src/
DIR_INC = ./include/
DIR_BUILD = ./build/
DIR_LIB = ./lib/
DIR_BIN = ./bin/


LINK = g++
LFLAGS = 
# LIBS = -L/usr/lib/i386-linux-gnu -lpthread
LIBS = -lpthread -I/usr/local/ssl/include/ -lssl -lcrypto  -ldl -L/usr/local/ssl/lib -L$(DIR_LIB) -lx264 -I$(DIR_INC)

INSTALL_FILE = install -m 777 -p

objects :=$(wildcard ${DIR_SRC}*.cpp)
objects +=$(wildcard ${DIR_SRC}*.c)

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
	$(CXX) $(LFLAGS) -o $@ $^ $(LIBS)
	mv $(all) $(DIR_BIN)

clean:
	-rm -f $(all) *.d *.o

install:
	-$(INSTALL_FILE) RTSP ~/Desktop
