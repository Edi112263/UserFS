#include <linux/fs.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/pagemap.h>

#define MAX_FILE_SIZE PAGE_SIZE * 1000;
#define USERFS_MAGIC 0x13371337
#define USERFS_DIRS_OFFSET 512

/* TODO: ATENTIE! DE ELIBERAT DENTRY-URILE ALOCATE?!!? */


/* Functie care creaza un nou inod si il initializeaza cu valori implicite */
struct inode *userfs_new_inode(struct super_block *sb, umode_t mode)
{
	struct inode *inode = new_inode(sb); /* Functie a sistemului de operare care aloca un inod */
	
	if (inode)
	{
		inode->i_mode = mode; /* Permisiuni */
		inode->i_blocks = 0; /* Numarul de blocuri(initial nu avem niciun bloc cu date) */
		inode->i_blkbits = inode->i_sb->s_blocksize_bits; /* Marimea unui block in biti(aceeasi ca a superblock-ului) */
		inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode); /* Timpul trunchiat la granularitatea fs-ului */
// 		inode->i_uid = inode->i_gid = 0;
		inode->i_ino = get_next_ino(); /* Numarul inodului */
	}
	
	return inode;
}


/* Functia care se apeleaza la fiecare citire dintr-un fisier(procs) */ 
static ssize_t userfs_file_read (struct file *file, char *usrbuf, 
			size_t count, loff_t *offset)
{
	char mesaj[] = "Te salut, utilizatorule!\n";
	static int completed = 0; /* TODO: Atentie la acest static, persista in mai multe instante ale userfs */
	
	if (completed)
		return 0;
	
	pr_info("Se citeste dintr-un fisier!\n");
	
	if (count > sizeof(mesaj))
		count = sizeof(mesaj);
	
	if (copy_to_user(usrbuf, mesaj, count) != 0)
		return -1; /* mai degraba errno.. */
	
	completed = 1;
	
	return count;
}

/* Functia care se apeleaza la fiecare deschidere a unui fisier(procs) */
static int userfs_file_open (struct inode *inode, struct file *file)
{
	pr_info("S-a deschis un fisier!\n");
	
	return 0;
}


/* Seteaza functiile ce vor fi apelate pentru diverse operatii I/O pe fisiere(procs) */
static const struct file_operations userfs_file_ops = 
{
		.open = userfs_file_open,
		.read = userfs_file_read
};


/* Creeaza un fisier si asociaza-i o intrare de tip dentry.
 * Foarte asemanatoare cu crearea unui director(userfs_create_dir).
 */
static struct dentry *userfs_create_file(struct super_block *sb,
			struct dentry *parent, char *name)
{
	struct inode *inode;
	struct dentry *dentry;
// 	struct qstr qname = QSTR_INIT(name, 5);
	umode_t mode = S_IRUSR | S_IWUSR; /* TODO: DE SCHIMBAT PERMISIUNEA! */
	
// 	dentry = d_lookup(parent, &qname);
// 	if (dentry)
// 	{
// 		pr_info("Am gasit deja %s\n", name);
// 		return dentry;
// 	}
	
	dentry = d_alloc_name(parent, name);
	if (!dentry)
		goto err;
	
	inode = userfs_new_inode(sb, mode);
	if (!inode)
		goto err_free;
	
	/* Fisierului i se asociaza alte operatii I/O decat cele ale unui director */
	inode->i_fop = &userfs_file_ops; 
		
	d_add(dentry, inode);
	
	return dentry;
	
	err_free:
		dput(dentry);
	err:
		return NULL;
}

/* Creeaza un director si asociaza-i o intrare de tip dentry.
 * Intrarile de tip dentry sunt folosite de kernel pentru parsarea cailor(path-urilor). 
 */
static struct dentry *userfs_create_dir(struct super_block *sb, 
			struct dentry *parent, char *name)
{
	struct inode *inode;
	struct dentry *dentry;
	//struct qstr qname = QSTR_INIT(name, 4);/* HARDCODAREEEEEE */
	umode_t mode = S_IFDIR | S_IRWXU; /* TODO: DE SCHIMBAT PERMISIUNEA! */
	
// 	dentry = d_lookup(parent, &qname);
// 	if (dentry)
// 	{
// 		pr_info("Am gasit deja %s\n", name);
// 		return dentry;
// 	}
	
	dentry = d_alloc_name(parent, name); /* Aloca o intrare dentry */
	if (!dentry)
		goto err;
	
	inode = userfs_new_inode(sb, mode); /* Aloca un nou inod */
	if (!inode)
		goto err_free;
	
	inode->i_fop = &simple_dir_operations; // &userfs_dir_ops
	
	/* Intrucat nu implementam operatii pe directoare(cum ar fi mkdir, rmdir)
	 * este suficient nu definim aceste operatii.
	 */
	inode->i_op  = &simple_dir_inode_operations; 
		
	d_add(dentry, inode); /* Adauga dentry-ul directorului creat in evidenta sistemului de operare */
	
	return dentry;
	
	err_free:
		dput(dentry); /* Elibereaza intrarea daca am intampinat o eroare */
	err:
		return NULL;
}


/* Creeaza directoarele pentru fiecare user si cate un fisier procs corespunzator */
static int userfs_root_readdir(struct file *file, struct dir_context *ctx)
{
	/* TODO: ATENTIE LA CONDITIILE DE CURSA! */
	/* TODO: MOMENTAN MERGE, DAR E CAM INEFICIENT(SE ALOCA MEMORIE IN PROSTIE!), DE MEMORY LEAK-URI NICI NU MAI VORBIM..*/
	/* TODO: STERGEREA DIRECTOARELOR PT USERI INACTIVI(oare ar trebui sa eliberez toate dentry-urile, asemanator cu proc?) */
	
	struct super_block *sb = file_inode(file)->i_sb;
	struct dentry *root = sb->s_root;
	int no_users = 3;
	int i;
	
	pr_info("Am intrat in root readdir\n");
	
	if (ctx->pos > USERFS_DIRS_OFFSET)
		return 0; /* nu mai avem ce citi */
		
	if (!dir_emit_dots(file, ctx)) /* trecem peste '.' si '..' */
		return 0;
	
	for (i = 0; i < no_users; i++)
	{
		struct dentry *dentry;
		struct dentry *dentry_procs;
		struct inode  *inode;
		char name[20]; /* TODO:  de schimbat aici */
		int len;
		
		len = snprintf(name, sizeof(name), "dir%d", i);
		dentry = userfs_create_dir(sb, root, name);
		
		if (!dentry)
		{
			pr_err("Eroare creare dir!\n");
			return -1; /* sau errno.. */
		}
		
		inode = d_inode(dentry);
		
		dentry_procs = userfs_create_file(sb, dentry, "procs");
		if (!dentry_procs)
		{
			pr_err("Eroare creare fisier procs!\n");
			return -1; /* sau errno! */
		}
		
		ctx->pos += 1;
		dir_emit(ctx, name, len, inode->i_ino, inode->i_mode >> 12);
		
	}
	
	ctx->pos = USERFS_DIRS_OFFSET + 1;
	
	return 0;
}


const struct super_operations userfs_sb_ops =
{
	.statfs    = simple_statfs,         /* Output pentru comenzile 'stat -f' sau 'df' */
	.drop_inode = generic_delete_inode  /* Se apeleaza la stergerea unui inod */
	
	/* TODO: show_options */
};

static const struct file_operations userfs_root_ops =
{
	.read = generic_read_dir,
	.iterate = userfs_root_readdir,
	.llseek = generic_file_llseek
};


/* Functie care initializeaza superblock-ul sistemului de fisiere */
int userfs_fill_sb(struct super_block *sb, void *data, int silent)
{
	struct inode *inode;
	
	sb->s_blocksize      = PAGE_SIZE;      /* Marimea block-ului in bytes*/
	sb->s_blocksize_bits = PAGE_SHIFT;     /* Marimea block-ului in biti */
	sb->s_maxbytes       = MAX_FILE_SIZE;  /* Marimea maxima a unui fisier */
	sb->s_time_gran      = 1;              /* Time granularity(precizie?) */
	sb->s_op             = &userfs_sb_ops; /* Operatii pe superblock */
	sb->s_magic          = USERFS_MAGIC;   /* Indentificatorul sistemului de fisiere */
	
	inode = userfs_new_inode(sb, S_IFDIR | S_IRWXU); /* Creeaza un nou inod. TODO: ATENTIE! DE SCHIMBAT PERMISIUNEA! */ 
	inode->i_fop = &userfs_root_ops; //&userfs_root_ops;
	inode->i_op = &simple_dir_inode_operations;
	sb->s_root = d_make_root(inode);                 /* Fa-l radacina. */
	
	if (!sb->s_root)
	{
		pr_err("Eroare alocare inod!\n");
// 		return -ENOMEM; /* Out of memory */
		return -1;
	}

	return 0;
}



/* Functie care intoarce un pointer catre directorul radacina */
struct dentry *userfs_mount(struct file_system_type *fs_type,
		int flags, const char *dev_name, void *data)
{
	/* mount_nodev este o functie a sistemului de operare care monteaza un
	 * sistem de fisiere ce nu are la baza un disk fizic. Parametrul userfs_fill_sb
	 * este un pointer catre functia care va incarca(initializa) superblock-ul sistemului de fisiere.
	 */
	
	return mount_nodev(fs_type, flags, data, userfs_fill_sb);
}


/* Structura care defineste sistemul de fisiere */
static struct file_system_type userfs_type =
{
	.name = "userfs", /* Numele sistemului de fisiere care se va folosi la montarea cu 'mount -t' */
	.owner = THIS_MODULE,
	.mount = userfs_mount, /* Functia care se va apela la montare */
	.kill_sb = kill_litter_super /* Functie a sistemului de operare care se va apela la demontare
									pentru a elibera structurile interne. */
};

static int userfs_init(void)
{
	/* Inregistreaza sistemul de fisiere in evidenta sistemului de operare */
	
	if (register_filesystem(&userfs_type) != 0)
	{
		pr_err("Eroare la inregistrarea UserFS!\n");
// 		return errno;
		return -1;
	}
	
	pr_info("Inregistrare UserFS - Succes!\n");
	return 0;
}

static void userfs_exit(void)
{
	/* Scoate sistemul de fisiere din evidenta sistemului de operare */
	
	if (unregister_filesystem(&userfs_type) != 0)
		pr_err("Eroare la deinregistrare\n"); //TODO: De schimbat mesajul!
	else
		pr_info("Deinregistrare UserFS - Succes!\n");
	
}


module_init(userfs_init);
module_exit(userfs_exit);

MODULE_LICENSE("GPL"); /* De schimbat! */
MODULE_DESCRIPTION("UserFS");
MODULE_AUTHOR("Eduard Ionut Vintila");

