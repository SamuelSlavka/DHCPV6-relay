CXX=g++
CXXFLAGS=-Wall -g
LDFLAGS=-lpcap

TARGET=d6r

srcfiles:=$(shell find . -name "*.cpp")
objects=$(subst .cpp,.o,$(srcfiles))

RM=rm -f

all: d6r

d6r: $(objects)
	$(CXX) $(CXXFLAGS) -o d6r $(objects) $(LDFLAGS)

clean: 
	$(RM) $(objects) d6r