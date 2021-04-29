# UserFS
Un pseduo-sistem de fisiere care afiseaza utilizatorii
activi din sistem si procesele asociate. Cand este montat, in radacina se vor gasi directoare
corespunzatoare fiecarui utilizator activ. In fiecare director se va gasi un fisier procs ce
contine lista aferenta de procese active.


Compilare:

	make
	
Utilizare:

	insmod userfs.ko

	mkdir -p mnt

	mount -t userfs userfs ./mnt
 
Eliberare:

	umount ./mnt
	rmmod userfs
