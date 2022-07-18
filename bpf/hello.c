#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/mount.h>

#define MAX_PATH_LEN 255
#define MAX_LOOP 20

struct data_t
{
    u32 pid;
    u32 ret ;
    u32 syscall;
    char path[MAX_PATH_LEN];
    char comm[TASK_COMM_LEN];
    
};

enum syscalls{
    unlink,
    rmdir,
    mkdir,
    mknod,
    symlink
};


BPF_PERF_OUTPUT(events);

static __always_inline int __submitentry(struct pt_regs *ctx,struct dentry *den, struct data_t *data, int len){
    struct qstr dn = {};
    bpf_probe_read(&dn, sizeof(dn), &den->d_name);
    bpf_probe_read(&data->path, len, dn.name);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 0;
}

static __always_inline int submitpath(struct pt_regs *ctx,const struct path *dir, struct dentry *dentry, struct data_t *data, int len){
    struct vfsmount *mnt = dir->mnt;
    struct dentry *root_mnt = NULL;
    struct dentry *den = NULL;
    __submitentry(ctx, dentry, data, len);
    //get mount root
    bpf_probe_read(&root_mnt, sizeof(struct dentry*), &mnt->mnt_root);
    bpf_probe_read(&den, sizeof(struct dentry*), &dir->dentry);
    #pragma unroll
    for (int i=0; i<MAX_LOOP; i++){
        __submitentry(ctx, den, data, len);
        if(den == root_mnt){
            goto out;
        }
        bpf_probe_read(&den, sizeof(struct dentry*), &den->d_parent);
    }
out:
    return 0;
}

static __always_inline int trace(struct pt_regs *ctx, const struct path *dir, struct dentry *dentry){
    struct data_t data ={};
    data.ret = 1;
    data.pid = bpf_get_current_pid_tgid() >> 32 ;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    submitpath(ctx,dir,dentry, &data, sizeof(data.path));
    return 0;
}

static __always_inline int traceret(struct pt_regs *ctx, const struct path *dir, struct dentry *dentry, enum syscalls syscall){
    struct data_t data ={};
    data.syscall = syscall;
    data.pid = bpf_get_current_pid_tgid() >> 32 ;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.ret = 0;
    events.perf_submit(ctx, &data, sizeof(struct data_t));
    return 0;
}

int trace_security_path_unlink(struct pt_regs *ctx, const struct path *dir, struct dentry *dentry){
    trace(ctx, dir, dentry);
    return 0;
}

int traceret_security_path_unlink(struct pt_regs *ctx, const struct path *dir, struct dentry *dentry){
    traceret(ctx, dir, dentry, unlink);
    return 0;
}

int trace_security_path_rmdir(struct pt_regs *ctx, const struct path *dir, struct dentry *dentry){
    trace(ctx, dir, dentry);
    return 0;
}

int traceret_security_path_rmdir(struct pt_regs *ctx, const struct path *dir, struct dentry *dentry){
    traceret(ctx, dir, dentry, rmdir);
    return 0;
}

int trace_security_path_mkdir(struct pt_regs *ctx, const struct path *dir, struct dentry *dentry){
    trace(ctx, dir, dentry);
    return 0;
}

int traceret_security_path_mkdir(struct pt_regs *ctx, const struct path *dir, struct dentry *dentry){
    traceret(ctx, dir, dentry, mkdir);
    return 0;
}

int trace_security_path_mknod(struct pt_regs *ctx, const struct path *dir, struct dentry *dentry){
    trace(ctx, dir, dentry);
    return 0;
}

int traceret_security_path_mknod(struct pt_regs *ctx, const struct path *dir, struct dentry *dentry){
    traceret(ctx, dir, dentry, mknod);
    return 0;
}

int trace_security_path_symlink(struct pt_regs *ctx, const struct path *dir, struct dentry *dentry){
    trace(ctx, dir, dentry);
    return 0;
}

int traceret_security_path_symlink(struct pt_regs *ctx, const struct path *dir, struct dentry *dentry){
    traceret(ctx, dir, dentry, symlink);
    return 0;
}