/*
    SysinternalsEBPF

    Copyright (c) Microsoft Corporation

    All rights reserved.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

//====================================================================
//
// getOffsets.c
//
// Module that does nothing, but has all the symbols we need as
// const globals, which can be extracted with extractOffsets.
//
//====================================================================

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/sched/signal.h>
#include <linux/tty.h>
#include <linux/device.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/skbuff.h>
#include "mount.h"
//#include "/usr/src/linux/fs/mount.h"
#include <linux/fdtable.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kevin Sheldrake");
MODULE_DESCRIPTION("Acquires offsets into structs as consts");
MODULE_VERSION("0.01");

// anonumous structs used in member calculations
struct task_struct *ts;
struct mount *mount;
struct sk_buff *skb;

// const arrays of struct member offsets; extract from module ELF with extract.c
const unsigned long parent[] =              {(void *)&ts->real_parent - (void *)ts};
const unsigned long pid[] =                 {(void *)&ts->tgid - (void *)ts};
const unsigned long ppid[] =                {(void *)&ts->real_parent - (void *)ts,
                                             (void *)&ts->tgid - (void *)ts};
#ifdef CONFIG_AUDIT
const unsigned long auid[] =                {(void *)&ts->loginuid - (void *)ts};
const unsigned long ses[] =                 {(void *)&ts->sessionid - (void *)ts};
#else
const unsigned long auid[] =                {-1};
const unsigned long ses[] =                 {-1};
#endif
#if KERN_MAJ == 4 || (KERN_MAJ == 5 && KERN_MIN < 5)
const unsigned long start_time[] =          {(void *)&ts->real_start_time - (void *)ts};
#else
const unsigned long start_time[] =          {(void *)&ts->start_boottime - (void *)ts};
#endif
#define CRED ts->cred
const unsigned long cred[] =                {(void *)&CRED - (void *)ts};
const unsigned long cred_uid[] =            {(void *)&CRED->uid - (void *)CRED};
const unsigned long cred_gid[] =            {(void *)&CRED->gid - (void *)CRED};
const unsigned long cred_euid[] =           {(void *)&CRED->euid - (void *)CRED};
const unsigned long cred_suid[] =           {(void *)&CRED->suid - (void *)CRED};
const unsigned long cred_fsuid[] =          {(void *)&CRED->fsuid - (void *)CRED};
const unsigned long cred_egid[] =           {(void *)&CRED->egid - (void *)CRED};
const unsigned long cred_sgid[] =           {(void *)&CRED->sgid - (void *)CRED};
const unsigned long cred_fsgid[] =          {(void *)&CRED->fsgid - (void *)CRED};
#define SS ts->signal
#define TTYS SS->tty
const unsigned long tty[] =                 {(void *)&SS - (void *)ts,
                                             (void *)&(SS->tty) - (void *)SS,
                                             (void *)&(TTYS->index) - (void *)TTYS};
const unsigned long comm[] =                {(void *)&ts->comm - (void *)ts};
#define MM ts->mm
#define EXE MM->exe_file
const unsigned long exe_path[] =            {(void *)&MM - (void *)ts,
                                             (void *)&EXE - (void *)MM,
                                             (void *)&EXE->f_path - (void *)EXE};
const unsigned long mm_arg_start[] =        {(void *)&MM - (void *)ts,
                                             (void *)&MM->arg_start - (void *)MM};
const unsigned long mm_arg_end[] =          {(void *)&MM - (void *)ts,
                                             (void *)&MM->arg_end - (void *)MM};
const unsigned long mm_start_code[] =       {(void *)&MM - (void *)ts,
                                             (void *)&MM->start_code - (void *)MM};
const unsigned long mm_end_code[] =         {(void *)&MM - (void *)ts,
                                             (void *)&MM->end_code - (void *)MM};
#define FS ts->fs
#define PWD FS->pwd
#define DENTRY PWD.dentry
#define INODE DENTRY->d_inode
const unsigned long pwd_path[] =            {(void *)&FS - (void *)ts,
                                             (void *)&PWD - (void *)FS};
const unsigned long path_vfsmount[] =       {(void *)&PWD.mnt - (void *)&PWD};
const unsigned long path_dentry[] =         {(void *)&DENTRY - (void *)&PWD};
const unsigned long dentry_parent[] =       {(void *)&DENTRY->d_parent - (void *)DENTRY};
const unsigned long dentry_iname[] =        {(void *)&DENTRY->d_iname - (void *)DENTRY};
const unsigned long dentry_name[] =         {(void *)&DENTRY->d_name.name - (void *)DENTRY};
const unsigned long dentry_inode[] =        {(void *)&INODE - (void *)DENTRY};
const unsigned long inode_mode[] =          {(void *)&INODE->i_mode - (void *)INODE};
const unsigned long inode_atime[] =         {(void *)&INODE->i_atime - (void *)INODE};
const unsigned long inode_mtime[] =         {(void *)&INODE->i_mtime - (void *)INODE};
const unsigned long inode_ctime[] =         {(void *)&INODE->i_ctime - (void *)INODE};
const unsigned long inode_ouid[] =          {(void *)&INODE->i_uid - (void *)INODE};
const unsigned long inode_ogid[] =          {(void *)&INODE->i_gid - (void *)INODE};
const unsigned long mount_mnt[] =           {(void *)&mount->mnt - (void *)mount};
const unsigned long mount_parent[] =        {(void *)&mount->mnt_parent - (void *)mount};
const unsigned long mount_mountpoint[] =    {(void *)&mount->mnt_mountpoint - (void *)mount};

#define FILES ts->files
#define FDTABLE FILES->fdt
const unsigned long max_fds[] =             {(void *)&FILES - (void *)ts,
                                             (void *)&FDTABLE - (void *)FILES,
                                             (void *)&FDTABLE->max_fds - (void *)FDTABLE};
const unsigned long fd_table[] =            {(void *)&FILES - (void *)ts,
                                             (void *)&FDTABLE - (void *)FILES,
                                             (void *)&FDTABLE->fd - (void *)FDTABLE};
const unsigned long fd_path[] =             {(void *)&EXE->f_path - (void *)EXE};
const unsigned long SKB_network_header[] =  {(void *)&skb->network_header - (void *)skb};
const unsigned long SKB_head[] =            {(void *)&skb->head - (void *)skb};
const unsigned long SKB_data[] =            {(void *)&skb->data - (void *)skb};
 
static int __init get_offsets_init(void) {
    printk(KERN_INFO "getOffsets loaded\n");
    return 0;
}

static void __exit get_offsets_exit(void) {
    printk(KERN_INFO "getOffsets unloaded\n");
}

module_init(get_offsets_init);
module_exit(get_offsets_exit);

