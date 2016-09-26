CFLAGS += -W -Wall

OBJS := main.o xrp_linux.o

default: share-context
clean:
	rm -f share-context $(OBJS)

share-context: $(OBJS) xrp_api.h
	$(CC) $(OBJS) -o $@ $(CFLAGS)
