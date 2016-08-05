CC = gcc
CFLAGS = -W
TARGET = send_arp_mitm

$(TARGET) :
	$(CC) $(CFLAGS) -o $(TARGET) send_arp_mitm.c -lpcap -lpthread -lnet

clean :
	rm $(TARGET)
