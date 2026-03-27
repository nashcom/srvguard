# srvguard C++ consumer
# Builds a static library and the example binary.
# No external dependencies — standard C++ and Linux syscalls only.

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2 -fPIC

TARGET_LIB  = libsrvguard.a
TARGET_EXE  = example

SRCS_LIB    = srvguard.cpp
SRCS_EXE    = example.cpp

OBJS_LIB    = $(SRCS_LIB:.cpp=.o)
OBJS_EXE    = $(SRCS_EXE:.cpp=.o)

.PHONY: all clean

all: $(TARGET_LIB) $(TARGET_EXE)

$(TARGET_LIB): $(OBJS_LIB)
	ar rcs $@ $^

$(TARGET_EXE): $(OBJS_EXE) $(TARGET_LIB)
	$(CXX) $(CXXFLAGS) -o $@ $^

%.o: %.cpp srvguard.hpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS_LIB) $(OBJS_EXE) $(TARGET_LIB) $(TARGET_EXE)
