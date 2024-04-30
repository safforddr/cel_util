
all: pcclient_to_cel systemd_log_to_cel ima-ng_to_cel cel_verify cel_fix_seq

cel_fix_seq: cel_fix_seq.c cel.h
	gcc -Wall -o cel_fix_seq cel_fix_seq.c
	
pcclient_to_cel: pcclient_to_cel.c cel.h
	gcc -Wall -o pcclient_to_cel pcclient_to_cel.c
	
ima-ng_to_cel: ima-ng_to_cel.c cel.h
	gcc -Wall -o ima-ng_to_cel ima-ng_to_cel.c

systemd_log_to_cel: systemd_log_to_cel.c cel.h
	gcc -I/usr/include/json-c -Wall -g -o systemd_log_to_cel systemd_log_to_cel.c -ljson-c
	
cel_verify: cel_verify.c pcclient_verify.c cel.h cel_verify.h pcclient.h pcclient_verify.h ima_template_verify.h ima_template_verify.c
	gcc -Wall -o cel_verify cel_verify.c pcclient_verify.c ima_template_verify.c -lssl -lcrypto

clean:
	rm -f *.o pcclient_to_cel systemd_log_to_cel ima-ng_to_cel cel_verify pc.cel systemd.cel ima.cel pcrs.bin cel_fix_seq
