
all : as clnt fs

as : as.o security.o sock.o  
	gcc -o as as.o security.o sock.o -lssl -lcrypto

clnt : clnt.o security.o sock.o
	gcc -o clnt clnt.o security.o sock.o -lssl -lcrypto

fs : fs.o security.o sock.o
	gcc -o fs fs.o security.o sock.o -lssl -lcrypto

clnt.o :
	gcc -c -o clnt.o my_clnt.c -lssl -lcrypto

as.o :
	gcc -c -o as.o my_as.c -lssl -lcrypto

fs.o :
	gcc -c -o fs.o my_fs.c -lssl -lcrypto

sock.o :
	gcc -c -o sock.o src/sock_.c

security.o :
	gcc -c -o security.o src/security.c

clean :
	rm *.o as clnt fs
