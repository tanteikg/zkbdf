TARGETS : zkboo_prove zkboo_verify zkbdf_eval zkbdf_verify zkbdf_verifyPseudo 

zkboo_prove : zkboo_prove.c zkboo_shared.h
	gcc -fopenmp zkboo_prove.c -o zkboo_prove -lssl -lcrypto

zkboo_verify : zkboo_verify.c zkboo_shared.h
	gcc -fopenmp zkboo_verify.c -o zkboo_verify -lssl -lcrypto

zkbdf_eval : zkbdf_eval.c shared.h
	gcc -fopenmp zkbdf_eval.c -o zkbdf_eval -lssl -lcrypto -lm

zkbdf_verify : zkbdf_verify.c shared.h
	gcc -fopenmp zkbdf_verify.c -o zkbdf_verify -lssl -lcrypto -lm

zkbdf_verifyPseudo : zkbdf_verifyPseudo.c shared.h
	gcc -fopenmp zkbdf_verifyPseudo.c -o zkbdf_verifyPseudo -lssl -lcrypto

clean :
	rm  zkboo_prove zkboo_verify zkbdf_eval zkbdf_verify zkbdf_verifyPseudo *.bin *.stackdump 


