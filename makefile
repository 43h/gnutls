all: client server

client: client.c
	gcc -o client client.c -lgnutls

server: server.c
	gcc -o server server.c -lgnutls -lpthread

clean:
	@rm -rf client server
