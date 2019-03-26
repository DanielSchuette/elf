# Makefile to compile 32- and 64-bit test binaries.
TARGET := elf

.PHONY: all clean test

all:
	# binaries
	gcc $(TARGET).c -o $(TARGET)_64bit
	gcc -m32 $(TARGET).c -o $(TARGET)_32bit
	# object files
	gcc $(TARGET).c -c -o $(TARGET)_64bit.o
	gcc -m32 $(TARGET).c -c -o $(TARGET)_32bit.o

test:
	@echo 'testing 64-bit binary'
	@./$(TARGET)_64bit
	@echo 'testing 32-bit binary'
	@./$(TARGET)_32bit

clean:
	rm -f $(TARGET)_* *.o
