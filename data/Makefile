# Makefile to compile 32- and 64-bit test binaries.
TARGET := elf

.PHONY: all clean test

all:
	gcc $(TARGET).c -o $(TARGET)_64bit
	gcc -m32 $(TARGET).c -o $(TARGET)_32bit

test:
	@echo 'testing 64-bit binary'
	@./$(TARGET)_64bit
	@echo 'testing 32-bit binary'
	@./$(TARGET)_32bit

clean:
	rm -f $(TARGET)_32bit $(TARGET)_64bit
