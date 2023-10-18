
all: pcclient_to_cel systemd_to_cel ima-ng_to_cel cel_verify

pcclient_to_cel: pcclient_to_cel.c cel.h
	gcc -Wall -o pcclient_to_cel pcclient_to_cel.c
	
ima-ng_to_cel: ima-ng_to_cel.c cel.h
	gcc -Wall -o ima-ng_to_cel ima-ng_to_cel.c

systemd_to_cel: systemd_to_cel.c cel.h
	gcc -Wall -o systemd_to_cel systemd_to_cel.c -lsystemd -lssl -lcrypto
	
cel_verify: cel_verify.c pcclient_verify.c cel.h cel_verify.h pcclient.h pcclient_verify.h ima_template_verify.h ima_template_verify.c
	gcc -Wall -o cel_verify cel_verify.c pcclient_verify.c ima_template_verify.c -lssl -lcrypto

clean:
	rm -f *.o pcclient_to_cel systemd_to_cel ima-ng_to_cel cel_verify pc.cel systemd.cel ima.cel pcrs.bin
