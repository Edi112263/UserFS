#include <linux/fs.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/mutex.h>

#define USERFS_MAGIC 0x13371337
#define USERFS_DIRS_OFFSET 1024
#define USERFS_MAX_USERS 512
#define USERFS_MAX_OUTPUT_SIZE 8192
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_RESET   "\x1b[0m"

DEFINE_MUTEX(userfs_mutex_turn);

/* Ture: folosite pentru a nu repeta afisarea unui director de mai multe ori in aceeasi parcurgere */
static long turn;
static long turns[USERFS_MAX_USERS]; // poate ar merge mai bine un malloc la userfs_init?
static int n;

/* Copiaza in bufferul 'name' numele utilizatorului cu uid-ul dat.
 * Daca nu exista, intoarce -1.
 * Intoarce 0 la succes.
 */ 
static int get_username(kuid_t uid, char *name, int size)
{
	/* Formatul din /etc/passwd:   user:pass:uid:restul */
	
	struct file *f;
	char buf[24]; // de verificat de ce nu merge cu 128!
	char *it;
	char username[32 + 1]; /* 32 e marimea maxima a numelui unui utilizator */
	char str_uid[8];
	loff_t pos = 0;
	long l_uid;
	kuid_t uid_passwd;
	ssize_t bytes = 0;
	int cnt = 0; /* Contor cu ajutorul caruia retinem unde am ramas cu cititul */
	bool ok_name = 0, ok_pass = 0, ok_uid = 0; /* 0 - nu am terminat de citit, 1 - citire finalizata */
	
	if (!name)
		return -1;
	
	f = filp_open("/etc/passwd", O_RDONLY, 0);
	if (!f)
	{
		pr_err("UserFS: Eroare deschidere /etc/passwd!\n");
		goto err;
	}
	
	while ((bytes = kernel_read(f, buf, sizeof(buf) - 1, &pos)) > 0 )
	{
		buf[bytes] = '\0';
		it = buf;
		
		if (ok_uid) /* Daca am terminat de citit uid-ul */
		{
			it = strchr(it, '\n'); /* Trecem la urmatoarea linie din fisier */
			if (!it)
				continue; /* Citim in continuare din fisier daca nu am gasit \n */
			
			it++; /* Trecem de '\n' */
			ok_name = ok_pass = ok_uid = 0; /* Resetem ok-urile */
			cnt = 0; /* Si contorul */
		} 
		
		if (!ok_name) /* Daca nu am terminat de citit numele */
		{
			for (; *it != ':' && *it != '\0'; cnt++, it++)
				username[cnt] = *it;
			
			username[cnt] = '\0';
			if (*it == '\0') /* Nu mai avem ce citi din buffer */
				continue;
			
			ok_name = 1; /* Altfel, am dat de ':', deci am terminat de citit numele */
			it++;
			cnt = 0; /* Resetam contorul */
		}
		
		if (!ok_pass) /* Daca nu am terminat de citit parola */
		{
			for (; *it != ':' && *it != '\0'; cnt++, it++); /* Sarim peste parola */
			
			if (*it == '\0') /* Nu mai avem ce citi din buffer */
				continue;
			
			ok_pass = 1; /* Altfel, am dat de ':', deci am terminat de citit parola */
			it++;
			cnt = 0; /* Resetam contorul, desi nu l-am folosit pt parola */
		}
		
		if (!ok_uid) /* Daca nu am terminat de citit uid-ul */
		{
			for (; *it != ':' && *it != '\0'; cnt++, it++)
				str_uid[cnt] = *it;
				
			str_uid[cnt] = '\0';
			if (*it == '\0') /* Nu mai avem ce citi din buffer */
				continue;
			
			ok_uid = 1; /* Altfel, am dat de ':', deci am terminat de citit uid-ul */
			if (kstrtol(str_uid, 10, &l_uid) != 0) /* Transformam string-ul in numar */
			{
				pr_err("UserFS: Eroare transformare string uid in int!\n");
				goto err;
			}
			uid_passwd = KUIDT_INIT(l_uid);
			
			if (!uid_eq(uid_passwd, uid))
				continue;
			
			strncpy(name, username, size);
			name[size] = '\0';
			goto done;
		}
	}
	/* Daca am ajuns pana aici, inseamna ca nu am gasit nimic..	*/
	
err:
	filp_close(f, NULL);
	return -1;
	
done:
	filp_close(f, NULL);
	return 0;
}

/* Creeaza un nou inod si initializeaza-l cu valori implicite */
struct inode *userfs_new_inode(struct super_block *sb, umode_t mode)
{
	struct inode *inode = new_inode(sb); /* Functie a sistemului de operare care aloca un inod */
	
	if (inode)
	{
		inode->i_mode = mode; /* Permisiuni */
		inode->i_blocks = 0; /* Numarul de blocuri(nu avem niciun bloc cu date) */
		inode->i_blkbits = inode->i_sb->s_blocksize_bits; /* Marimea unui block in biti(aceeasi ca a superblock-ului) */
		inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode); /* Timpul trunchiat la granularitatea fs-ului */
		inode->i_ino = get_next_ino(); /* Numarul inodului */
	}
	
	return inode;
}


/* Se apeleaza la fiecare citire din fisierul procs */ 
static ssize_t userfs_file_read (struct file *file, char *usrbuf, 
			size_t count, loff_t *offset)
{
	char *msg = kmalloc(USERFS_MAX_OUTPUT_SIZE, GFP_KERNEL);
	char heading[] = "PID     Nume";
	int bytes = 0;
	struct task_struct *task;
	struct dentry *parent = file_dentry(file)->d_parent;
	char *username = parent->d_iname;
	long dif = USERFS_MAX_OUTPUT_SIZE - *offset;
	ssize_t len = (count < dif) ? count : dif; /* Cat citim */
	
	if (len <= 0)
		return 0; /* Marcheaza EOF */
	
	bytes += snprintf(msg, USERFS_MAX_OUTPUT_SIZE, COLOR_GREEN "%s\n" COLOR_RESET, heading);
	
	rcu_read_lock();
	for_each_process(task)
	{
		kuid_t task_uid;
		char task_username[33];
		
		task_lock(task);
		task_uid = task->cred->uid;
		
		if (!get_username(task_uid, task_username, sizeof(username)))
		{
			if (!strcmp(task_username, username))
			{
				if (bytes >= USERFS_MAX_OUTPUT_SIZE)
				{
					task_unlock(task);
					break;
				}
				bytes += snprintf(msg + bytes, USERFS_MAX_OUTPUT_SIZE - bytes, 
								"%-7d %s\n", (int) task_pid_nr(task), task->comm);
			}
		}
		else
		{
			pr_err("UserFS: Eroare aflare nume UID: %u\n", task_uid.val);
			return 0;
		}
		task_unlock(task);
		
	}
	rcu_read_unlock();
		
	if (*offset > bytes) /* Daca indicatorul de pozitie depaseste numarul de bytes pe care ii citim */
		return 0; /* EOF */
		
	if (copy_to_user(usrbuf, msg + *offset, len) != 0)
		return -1; /* mai degraba errno.. */
	
	kfree(msg);
	
	*offset += len; /* Deplaseaza indicatorul de pozitie */
	return len;
}

void userfs_dentry_release(struct dentry *dentry)
{
	pr_info("UserFS: Se dezaloca dentry-ul: %s\n", dentry->d_iname);
	if (dentry->d_inode)
		clear_inode(dentry->d_inode);
}


/* Seteaza functiile ce vor fi apelate pentru diverse operatii I/O pe fisiere(procs) */
static const struct file_operations userfs_file_ops = 
{
		.read = userfs_file_read
};

static const struct dentry_operations userfs_dentry_ops = 
{
		.d_release = userfs_dentry_release
};


/* Creeaza un fisier procs si asociaza-i o intrare de tip dentry.
 * Foarte asemanatoare cu crearea unui director(userfs_create_dir).
 */
int userfs_create_file(struct super_block *sb,
			struct dentry *parent, char *name, int len)
{
	struct inode *inode;
	struct dentry *dentry;
	struct qstr qname = QSTR_INIT(name, len);
	umode_t mode = S_IRUGO;
	
	dentry = d_hash_and_lookup(parent, &qname);
	if (dentry && dentry->d_inode)
	{
		dput(dentry);
		return 0;
	}
	
	if (!dentry)
	{
		dentry = d_alloc(parent, &qname); /* Aloca o intrare dentry */
		if (!dentry)
			goto err;
	}
	
	dentry->d_op = &userfs_dentry_ops;
	inode = userfs_new_inode(sb, mode); /* Aloca un nou inod */
	if (!inode)
		goto err_free;
	
	inode->i_fop = &userfs_file_ops;
	
	d_add(dentry, inode); /* Adauga dentry-ul directorului creat in evidenta sistemului de operare */

	dput(dentry);
	return 0;
	
	err_free:
		dput(dentry);//d_drop(dentry); /* Elibereaza intrarea daca am intampinat o eroare */
	err:
		return -1;
}

/* Creeaza un director si asociaza-i o intrare de tip dentry.
 * Intrarile de tip dentry sunt folosite de kernel pentru parsarea cailor(path-urilor). 
 */
int userfs_create_dir(struct super_block *sb, struct dentry *parent,
			struct dir_context *ctx, char *name, int len)
{
	struct inode *inode;
	struct dentry *dentry;
	struct qstr qname = QSTR_INIT(name, len);
	umode_t mode = S_IFDIR | S_IXUGO | S_IRUGO; 
	
	dentry = d_hash_and_lookup(parent, &qname); /* Cauta daca am creat deja intrarea */
	if (dentry && dentry->d_inode)
	{
		int *fsdata = dentry->d_fsdata;
		
		if (*fsdata == turn) /* Am afisat deja directorul tura asta */
		{
			dput(dentry); /* Dupa hash_and_lookup trebuie scazut ref count-ul pt dentry */
			return 0;
		}
		
		*fsdata = turn; /* Marcheaza ca am afisat tura asta */
		inode = dentry->d_inode;
		dput(dentry);
		ctx->pos += 1;
		/* Paseaza informatii despre director catre cel care face citirea */
		return dir_emit(ctx, name, len, inode->i_ino, inode->i_mode >> 12); 
	}
	if (!dentry) // daca nu intra pe ramura asta, inseamna ca dentryul nu are un inod asociat
	{
		dentry = d_alloc(parent, &qname); /* Aloca o intrare dentry */
		if (!dentry)
			goto err;
	}
	
	dentry->d_op = &userfs_dentry_ops;
	inode = userfs_new_inode(sb, mode); /* Aloca un nou inod */
	if (!inode)
		goto err_free;
	
	turns[n] = turn;
	dentry->d_fsdata = &turns[n];
	n = (n + 1) % USERFS_MAX_USERS;
	
	inode->i_fop = &simple_dir_operations; 
	inode->i_op  = &simple_dir_inode_operations; 
	d_add(dentry, inode); /* Asociasa dentry-ul cu inodul directorului */
	
	if (userfs_create_file(sb, dentry, "procs", 5) != 0)
		goto err_free;
		
	dput(dentry);
	ctx->pos += 1;
	return dir_emit(ctx, name, len, inode->i_ino, inode->i_mode >> 12); /* Aici s-ar putea sa intoarca 1 la succes */
	
	err_free:
		dput(dentry);
	err:
		return -1;
}


/* Se apeleaza la parcurgerea directorului radacina */
static int userfs_root_readdir(struct file *file, struct dir_context *ctx)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct dentry *root = sb->s_root;
	struct task_struct *task;
	
	if (ctx->pos > USERFS_DIRS_OFFSET)
		return 0; /* nu mai avem ce citi */
		
	if (!dir_emit_dots(file, ctx)) /* trecem peste '.' si '..' */
		return 0;
	
	mutex_lock(&userfs_mutex_turn);
	rcu_read_lock();
	for_each_process(task)
	{
		char username[33];
		int len;
		kuid_t uid;
		
		task_lock(task);
		uid = task->cred->uid; /* Preia uid-ul procesului */
		task_unlock(task);
		
		get_username(uid, username, sizeof(username));
		if (!get_username(uid, username, sizeof(username)))
		{
			len = strlen(username);
			userfs_create_dir(sb, root, ctx, username, len); /* Aici de verificat eroare */
		}
		else
		{
			pr_err("UserFS: Eroare aflare nume UID: %u\n", uid.val);
		}
	}
	rcu_read_unlock();
	turn++;
	mutex_unlock(&userfs_mutex_turn);
	
	ctx->pos = USERFS_DIRS_OFFSET + 1; /* Marcam ca am terminat parcurgerea */
	return 0;
}

/* Se apeleaza cand se cauta o intrare specifica din directorul radacina */
static struct dentry *userfs_root_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	struct task_struct *task;
	const char *username = dentry->d_iname; /* Numele cautat */
	
	rcu_read_lock();
	for_each_process(task)
	{
		char task_username[33];
		kuid_t task_uid;
		
		task_lock(task);
		task_uid = task->cred->uid; /* Preia uid-ul procesului*/
		task_unlock(task);
		
		if (!get_username(task_uid, task_username, sizeof(username)))
		{
			if (!strcmp(task_username, username))
			{
				umode_t mode = S_IFDIR | S_IXUGO | S_IRUGO;
				struct inode *inode = userfs_new_inode(dir->i_sb, mode);
				
				if (!inode)
				{
					pr_err("UserFS: Eroare alocare inod lookup\n");
					return ERR_PTR(-1);
				}
				
				dentry->d_op = &userfs_dentry_ops;
				inode->i_fop = &simple_dir_operations;
				inode->i_op = &simple_dir_inode_operations;
				
				mutex_lock(&userfs_mutex_turn);
				dentry->d_fsdata = &turns[n];
				n = (n + 1) % USERFS_MAX_USERS;
				mutex_unlock(&userfs_mutex_turn);
				
				d_add(dentry, inode);
				userfs_create_file(dir->i_sb, dentry, "procs", 5);
				
				// ceva cu icount?
				rcu_read_unlock();
				return NULL;
			}
		}
		else
		{
			pr_err("UserFS: Eroare aflare nume UID: %u\n", task_uid.val);
		}
		
	}
	rcu_read_unlock();
	
	d_add(dentry, NULL);
	return NULL;
}


const struct super_operations userfs_sb_ops =
{
	.statfs    = simple_statfs,         /* Output pentru comenzile 'stat -f' sau 'df' */
	.drop_inode = generic_delete_inode  /* Se apeleaza la stergerea unui inod */
};

static const struct file_operations userfs_root_ops =
{
	.read = generic_read_dir,
	.iterate = userfs_root_readdir,
	.llseek = generic_file_llseek
};

static const struct inode_operations userfs_root_inode_ops = 
{
	.lookup = userfs_root_lookup
};


/* Initializeaza superblock-ul sistemului de fisiere(practic metadate despre acesta) */
int userfs_fill_sb(struct super_block *sb, void *data, int silent)
{
	struct inode *inode;
	
	sb->s_blocksize      = PAGE_SIZE;      /* Marimea block-ului in bytes*/
	sb->s_blocksize_bits = PAGE_SHIFT;     /* Marimea block-ului in biti */
	sb->s_time_gran      = 1;              /* Time granularity(precizie?) */
	sb->s_op             = &userfs_sb_ops; /* Operatii pe superblock */
	sb->s_magic          = USERFS_MAGIC;   /* Indentificatorul sistemului de fisiere */
	
	inode = userfs_new_inode(sb, S_IFDIR | S_IXUGO | S_IRUGO); /* Creeaza un nou inod. */
	inode->i_fop = &userfs_root_ops;
	inode->i_op = &userfs_root_inode_ops;
	sb->s_root = d_make_root(inode);                 /* Fa-l radacina. */
	
	if (!sb->s_root)
	{
		pr_err("UserFS: Eroare alocare inod!\n");
		return -ENOMEM;
	}

	return 0;
}



/* Intoarce un pointer catre directorul radacina */
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
	.kill_sb = kill_anon_super /* Functie a sistemului de operare care se va apela la demontare
									pentru a elibera structurile interne. */
};

static int userfs_init(void)
{
	/* Inregistreaza sistemul de fisiere in evidenta sistemului de operare */
	int errno;
	
	if ((errno = register_filesystem(&userfs_type)) != 0)
	{
		pr_err("UserFS: Eroare la inregistrarea UserFS!\n");
		return errno;
	}
	
	pr_info("UserFS: Inregistrare - Succes!\n");
	return 0;
}

static void userfs_exit(void)
{
	/* Scoate sistemul de fisiere din evidenta sistemului de operare */
	
	if (unregister_filesystem(&userfs_type) != 0)
		pr_err("UserFS: Eroare la deinregistrare\n");
	else
		pr_info("UserFS: Deinregistrare - Succes!\n");
	
}


module_init(userfs_init);
module_exit(userfs_exit);

MODULE_LICENSE("GPL"); /* De schimbat! */
MODULE_DESCRIPTION("UserFS");
MODULE_AUTHOR("Eduard Ionut Vintila");
