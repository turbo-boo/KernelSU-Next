#include <linux/version.h>
#include <linux/fs.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#include <linux/sched/task.h>
#else
#include <linux/sched.h>
#endif
#include <linux/uaccess.h>
#include <linux/fdtable.h>
#include <linux/key.h>
#include <linux/cred.h>
#include "klog.h" // IWYU pragma: keep
#include "kernel_compat.h"

#ifdef KSU_HAS_INIT_SESSION_KEYRING
static struct key *init_session_keyring __read_mostly;
static bool init_session_keyring_closed __read_mostly;

/*
 * Capture init's session keyring the first time one is available.
 *
 * init installs its session keyring early in second stage and vold then links
 * the "fscrypt" keyring into it, so the first key operation init performs may
 * still observe a NULL session keyring.  Retry on later operations instead of
 * latching the NULL.
 *
 * Called from the key_permission LSM hook, the only place we see init's creds.
 * That hook cannot be unregistered on this kernel, so teardown is handled by
 * the closed flag: a capture that races with release undoes itself.
 */
void ksu_compat_capture_session_keyring(const struct cred *cred)
{
	struct key *keyring;

	if (READ_ONCE(init_session_keyring_closed))
		return;
	if (READ_ONCE(init_session_keyring) != NULL)
		return;

	rcu_read_lock();
	keyring = key_get(rcu_dereference(cred->session_keyring));
	rcu_read_unlock();
	if (!keyring) {
		// Not installed yet, retry on the next key operation.
		return;
	}

	if (cmpxchg(&init_session_keyring, NULL, keyring)) {
		// Another thread captured it first.
		key_put(keyring);
		return;
	}

	if (READ_ONCE(init_session_keyring_closed)) {
		// Raced with teardown; give the reference back.
		key_put(xchg(&init_session_keyring, NULL));
		return;
	}

	pr_info("kernel_compat: got init_session_keyring\n");
}

/*
 * Clone @base and install init's session keyring into the copy.
 *
 * The copy keeps every attribute of @base - notably its SELinux context and
 * capabilities - and only adds the session keyring that holds the FBE/fscrypt
 * "logon" keys.  It is used with override_creds()/revert_creds() around the
 * allowlist save so that the request_key() performed by ext4/f2fs can find the
 * encryption key even when the caller is a workqueue worker, which has no
 * session keyring of its own.
 *
 * Neither @base nor the caller's credentials are modified.
 *
 * Returns NULL when no keyring has been captured or when it is no longer
 * usable, in which case the caller falls back to @base alone.
 */
struct cred *ksu_compat_prepare_session_cred(const struct cred *base)
{
	const struct cred *saved;
	struct key *keyring;
	struct cred *cred;

	if (!base)
		return NULL;

	rcu_read_lock();
	keyring = key_get(rcu_dereference(init_session_keyring));
	rcu_read_unlock();
	if (!keyring)
		return NULL;

	/* init may have replaced or revoked the keyring after we cached it */
	if (key_validate(keyring)) {
		key_put(keyring);
		return NULL;
	}

	/*
	 * prepare_creds() clones current's credentials, so temporarily assume
	 * @base in order to inherit its SELinux context.
	 */
	saved = override_creds(base);
	cred = prepare_creds();
	revert_creds(saved);
	if (!cred) {
		key_put(keyring);
		return NULL;
	}

	/*
	 * Release the reference prepare_creds() took on the cloned session
	 * keyring; we are replacing it, not adding to it.
	 */
	key_put(cred->session_keyring);
	rcu_assign_pointer(cred->session_keyring, keyring);
	return cred;
}

/*
 * Drop the reference taken by ksu_compat_capture_session_keyring() and stop
 * capturing, so no reference can outlive the module.
 * Called at module teardown, after synchronize_rcu().
 */
void ksu_compat_release_session_keyring(void)
{
	WRITE_ONCE(init_session_keyring_closed, true);
	key_put(xchg(&init_session_keyring, NULL));
}
#endif /* KSU_HAS_INIT_SESSION_KEYRING */


struct file *ksu_filp_open_compat(const char *filename, int flags, umode_t mode)
{
	return filp_open(filename, flags, mode);
}

ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count,
			       loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0) ||                          \
	defined(KSU_OPTIONAL_KERNEL_READ)
	return kernel_read(p, buf, count, pos);
#else
	loff_t offset = pos ? *pos : 0;
	ssize_t result = kernel_read(p, offset, (char *)buf, count);
	if (pos && result > 0) {
		*pos = offset + result;
	}
	return result;
#endif
}

ssize_t ksu_kernel_write_compat(struct file *p, const void *buf, size_t count,
				loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0) ||                          \
	defined(KSU_OPTIONAL_KERNEL_WRITE)
	return kernel_write(p, buf, count, pos);
#else
	loff_t offset = pos ? *pos : 0;
	ssize_t result = kernel_write(p, buf, count, offset);
	if (pos && result > 0) {
		*pos = offset + result;
	}
	return result;
#endif
}


#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0) && !defined(KSU_HAS_PATH_MOUNT))
extern long do_mount(const char *dev_name, const char __user *dir_name,
		     const char *type_page, unsigned long flags,
		     void *data_page);

int path_mount(const char *dev_name, struct path *path, const char *type_page,
	       unsigned long flags, void *data_page)
{
	mm_segment_t old_fs;
	long ret = 0;
	char buf[384];

	char *realpath = d_path(path, buf, sizeof(buf));
	if (IS_ERR(realpath)) {
		pr_err("ksu_mount: d_path failed, err: %lu\n",
		       PTR_ERR(realpath));
		return PTR_ERR(realpath);
	}

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = do_mount(dev_name, (const char __user *)realpath, type_page,
		       flags, data_page);
	set_fs(old_fs);
	return ret;
}
#endif

long ksu_copy_from_user_nofault(void *dst, const void __user *src, size_t size)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    return copy_from_user_nofault(dst, src, size);
#else
    // https://elixir.bootlin.com/linux/v5.8/source/mm/maccess.c#L205
    long ret = -EFAULT;
    mm_segment_t old_fs = get_fs();

    set_fs(USER_DS);
    // tweaked to use ksu_access_ok
    if (ksu_access_ok(src, size)) {
        pagefault_disable();
        ret = __copy_from_user_inatomic(dst, src, size);
        pagefault_enable();
    }
    set_fs(old_fs);

    if (ret)
        return -EFAULT;
    return 0;
#endif
}

#ifndef KSU_OPTIONAL_STRNCPY
long strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr,
				   long count)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
	return strncpy_from_unsafe_user(dst, unsafe_addr, count);
#else
	mm_segment_t old_fs = get_fs();
	long ret;

	if (unlikely(count <= 0))
		return 0;

	set_fs(USER_DS);
	pagefault_disable();
	ret = strncpy_from_user(dst, unsafe_addr, count);
	pagefault_enable();
	set_fs(old_fs);

	if (ret >= count) {
		ret = count;
		dst[ret - 1] = '\0';
	} else if (ret > 0) {
		ret++;
	}

	return ret;
#endif
}
#endif // #ifndef KSU_OPTIONAL_STRNCPY

static void *__kvmalloc(size_t size, gfp_t flags)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
// https://elixir.bootlin.com/linux/v4.4.302/source/security/apparmor/lib.c#L79
	void *buffer = NULL;

	if (size == 0)
		return NULL;

	/* do not attempt kmalloc if we need more than 16 pages at once */
	if (size <= (16 * PAGE_SIZE))
		buffer = kmalloc(size, flags | GFP_NOIO | __GFP_NOWARN);
	if (!buffer) {
		if (flags & __GFP_ZERO)
			buffer = vzalloc(size);
		else
			buffer = vmalloc(size);
	}
	return buffer;
#else
	return kvmalloc(size, flags);
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
// https://elixir.bootlin.com/linux/v5.10.247/source/mm/util.c#L664
void *ksu_compat_kvrealloc(const void *p, size_t oldsize, size_t newsize,
			   gfp_t flags)
{
	void *newp;

	if (oldsize >= newsize)
		return (void *)p;
	newp = __kvmalloc(newsize, flags);
	if (!newp)
		return NULL;
	memcpy(newp, p, oldsize);
	kvfree(p);
	return newp;
}
#endif
