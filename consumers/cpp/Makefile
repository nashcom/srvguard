# srvguard C++ consumer
# Builds the static library, the example demo binary, and (when the Notes
# C-API is available) the domsrvguard Extension Manager shared library.
#
# Set LOTUS and Notes_ExecDirectory to include domsrvguard.so in the default build:
#   export LOTUS=/opt/hcl/domino
#   export Notes_ExecDirectory=/opt/hcl/domino/notes/latest/linux
#   make

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2 -fPIC

# Inject shared secret at build time when SRVGUARD_BUILD_SALT is set.
# Both srvguard (Go) and domsrvguard (C++) must be built with the same value.
# Generate a value: od -An -tx1 -N32 /dev/urandom | tr -d ' \n'
ifdef SRVGUARD_BUILD_SALT
CXXFLAGS += -DKEYRING_BUILD_SALT=\"$(SRVGUARD_BUILD_SALT)\"
endif

# ── Notes C-API settings (domsrvguard only) ───────────────────────────────

NOTESDIR ?= $(Notes_ExecDirectory)
INCDIR   ?= $(LOTUS)/notesapi/include

NOTES_DEFINES = -DGCC3 -DGCC4 -fno-strict-aliasing -DGCC_LBLB_NOT_SUPPORTED \
                -DUNIX -DLINUX -DLINUX86 -DND64 -DLINUX64 -DW -DLINUX86_64  \
                -DDTRACE -DPTHREAD_KERNEL -D_REENTRANT                        \
                -DUSE_THREADSAFE_INTERFACES -D_POSIX_THREAD_SAFE_FUNCTIONS    \
                -DHANDLE_IS_32BITS -DHAS_IOCP -DHAS_BOOL -DHAS_DLOPEN        \
                -DUSE_PTHREAD_INTERFACES -DLARGE64_FILES -D_LARGEFILE_SOURCE  \
                -D_LARGEFILE64_SOURCE -DNDUNIX64 -DLONGIS64BIT               \
                -DPRODUCTION_VERSION -DOVERRIDEDEBUG -Wno-write-strings

NOTES_LINKOPTS = -shared -fpic -Wl,-R$(NOTESDIR),-ztext
NOTES_LIBS     = -lnotes -lm -lpthread -lc -lresolv -ldl

# ── Targets ───────────────────────────────────────────────────────────────

TARGET_LIB = libsrvguard.a
TARGET_EXE = example
TARGET_DOM = domsrvguard.so

SRCS_LIB   = srvguard.cpp
SRCS_EXE   = example.cpp
SRCS_DOM   = domsrvguard.cpp

OBJS_LIB   = $(SRCS_LIB:.cpp=.o)
OBJS_EXE   = $(SRCS_EXE:.cpp=.o)
OBJS_DOM   = $(SRCS_DOM:.cpp=.o.notes)

ALL_TARGETS = $(TARGET_LIB) $(TARGET_EXE)
ifneq ($(and $(LOTUS),$(Notes_ExecDirectory)),)
ALL_TARGETS += $(TARGET_DOM)
endif

.PHONY: all domsrvguard clean

all: $(ALL_TARGETS)

domsrvguard: $(TARGET_DOM)

$(TARGET_LIB): $(OBJS_LIB)
	ar rcs $@ $^

$(TARGET_EXE): $(OBJS_EXE) $(TARGET_LIB)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(TARGET_DOM): $(OBJS_DOM) $(TARGET_LIB)
	$(CXX) $(NOTES_LINKOPTS) $^ -L$(NOTESDIR) -Wl,-rpath-link $(NOTESDIR) \
	    $(NOTES_LIBS) -o $@

%.o.notes: %.cpp srvguard.hpp
	$(CXX) -c -m64 $(NOTES_DEFINES) -I$(INCDIR) $(CXXFLAGS) -o $@ $<

%.o: %.cpp srvguard.hpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS_LIB) $(OBJS_EXE) $(OBJS_DOM) \
	      $(TARGET_LIB) $(TARGET_EXE) $(TARGET_DOM)
