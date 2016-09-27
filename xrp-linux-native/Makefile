CFLAGS += -W -Wall -I.. -g

OBJS := main.o xrp_linux_native.o

default: linux-native-test
clean:
	rm -f linux-native-test $(OBJS)

linux-native-test: $(OBJS) ../xrp_api.h
	$(CC) $(OBJS) -o $@ $(CFLAGS)
