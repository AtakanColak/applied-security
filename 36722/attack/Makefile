all:
	gcc -std=c99 -Wall -lm -o3 -o attack Source/attack.c
tryport:

	gcc -std=c99 -Wall -o3 -o tryport -I/opt/libserialport/0.1.1/include -L/opt/libserialport/0.1.1/lib -static Source/tryport.c -lserialport 

clean:
	# rm attack
	rm tryport
