TARGETS : zkboo_prove.exe zkboo_verify.exe zkbdf_eval.exe zkbdf_verify.exe zkbdf_verifyPCP.exe 

zkboo_prove.exe : zkboo_prove.c zkboo_shared.h
	gcc -Wl,--stack,16777216 -fopenmp zkboo_prove.c -o zkboo_prove.exe -lssl -lcrypto

zkboo_verify.exe : zkboo_verify.c zkboo_shared.h
	gcc -Wl,--stack,16777216 -fopenmp zkboo_verify.c -o zkboo_verify.exe -lssl -lcrypto

zkbdf_eval.exe : zkbdf_eval.c shared.h
	gcc -g -Wl,--stack,16777216 -fopenmp zkbdf_eval.c -o zkbdf_eval.exe -lssl -lcrypto

zkbdf_verify.exe : zkbdf_verify.c shared.h
	gcc -g -Wl,--stack,16777216 -fopenmp zkbdf_verify.c -o zkbdf_verify.exe -lssl -lcrypto

zkbdf_verifyPCP.exe : zkbdf_verifyPCP.c shared.h
	gcc -g -Wl,--stack,16777216 -fopenmp zkbdf_verifyPCP.c -o zkbdf_verifyPCP.exe -lssl -lcrypto

clean :
	rm  zkboo_prove.exe zkboo_verify.exe zkbdf_eval.exe zkbdf_verify.exe zkbdf_verifyPCP.exe *.bin *.stackdump 


