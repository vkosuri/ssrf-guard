CXX      := g++
CXXFLAGS := -std=c++11 -O2 -Wall -Wextra -Wpedantic
DEBUGFLAGS := -std=c++11 -g -O0 -Wall -Wextra -Wpedantic

# Library build
LIB_SRC    := ssrf_guard.cpp
LIB_OBJ    := ssrf_guard.o
LIB_STATIC := libssrf_guard.a

# Test executable
TEST_SRC   := test_ssrf.cpp
TEST_BIN   := test_ssrf

# Example executable
EXAMPLE_SRC := example.cpp
EXAMPLE_BIN := example

.PHONY: all lib test clean run run-test example clean-all

# Default: build library and test
all: lib test

# Build static library
lib: $(LIB_STATIC)

$(LIB_OBJ): $(LIB_SRC) ssrf_guard.h
	$(CXX) $(CXXFLAGS) -c $(LIB_SRC) -o $(LIB_OBJ)

$(LIB_STATIC): $(LIB_OBJ)
	ar rcs $(LIB_STATIC) $(LIB_OBJ)
	@echo "Static library $(LIB_STATIC) created"

# Build test executable (links against library)
test: $(TEST_BIN)

$(TEST_BIN): $(TEST_SRC) $(LIB_STATIC) ssrf_guard.h
	$(CXX) $(CXXFLAGS) $(TEST_SRC) -L. -lssrf_guard -o $(TEST_BIN)
	@echo "Test executable $(TEST_BIN) created"

# Build example executable (links against library)
example: $(EXAMPLE_BIN)

$(EXAMPLE_BIN): $(EXAMPLE_SRC) $(LIB_STATIC) ssrf_guard.h
	$(CXX) $(CXXFLAGS) $(EXAMPLE_SRC) -L. -lssrf_guard -o $(EXAMPLE_BIN)
	@echo "Example executable $(EXAMPLE_BIN) created"

# Run test suite
run: test
	./$(TEST_BIN)

run-test: run

# Debug build
debug: CXXFLAGS = $(DEBUGFLAGS)
debug: clean all

# Clean all builds
clean:
	rm -f $(LIB_OBJ) $(LIB_STATIC) $(TEST_BIN) $(EXAMPLE_BIN)

clean-all: clean
	rm -f *~ *.o
	@echo "Cleaned all files"

