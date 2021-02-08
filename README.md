# UserFS
Compilare:
	make
	
Utilizare:
	insmod userfs.ko
	mkdir -p mnt
	mount -t userfs userfs ./mnt
 
Eliberare:
	rmmod userfs
