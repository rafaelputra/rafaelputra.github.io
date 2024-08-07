---
layout: post
author: Rafael Putra
---

Beberapa hari terakhir saya iseng membaca *source code* linux dari github dan secara khusus tertarik dengan bahasan system call. Maka pada tulisan kali ini, saya tuliskan sedikit catatan tentang cara kerja syscall.

## Linux vs GNU/Linux
Terdapat kesalahpahaman tentang dua hal ini, maka sebelum memahami lebih jauh tentang linux, alangkah baiknya kita perbaiki hal ini terlebih dahulu. Ketika yang menjadi pokok bahasan adalah linux, itu hanya merujuk pada kernelnya saja, bukan sebagai sistem operasi. Hal ini sering menjadi miskonsepsi, seolah-olah keduanya sama, padahal memiliki pengertian masing-masing. Linux merupakan kernel atau inti pada suatu sistem operasi yang dikembangkan oleh Linus Torvalds pada 1991 dan didistribusikan secara bebas. GNU/Linux adalah sistem operasi yang dikembangkan oleh Richard Stallman dari Free Software Foundation yang menggunakan kernel linux. 

## Kernel
<p align="center"><img src="https://upload.wikimedia.org/wikipedia/commons/thumb/8/8f/Kernel_Layout.svg/300px-Kernel_Layout.svg.png"></p>
Semua sistem operasi memiliki kernel, karena kernel menjadi inti dari sistem operasi. Ketika kita mengakses aplikasi tertentu, aplikasi tersebut akan menggunakan kernel sebagai perantara antara aplikasi dengan <i>hardware</i> komputer.
<p align="center"><img src="https://upload.wikimedia.org/wikipedia/commons/thumb/2/2f/Priv_rings.svg/300px-Priv_rings.svg.png"></p>
Pada gambar terlihat bahwa pada <i>kernel mode</i> memiliki <i>privileged</i> yang lebih tinggi dibandingkan menggunakan <i>user mode</i>, karena pada <i>kernel mode</i> langsung berhadapan dengan fungsi-fungsi komputer. Ketika kita menggunakan aplikasi, kita berada pada <i>user mode</i> kemudian aplikasi tersebut akan mengakses kernel sehingga beralih menjadi <i>kernel mode</i> untuk mengakses beberapa fungsi kernel, setelah berhasil mengakses fungsi kernel yang digunakan aplikasi, maka outputnya akan di <i>return</i> ke <i>user mode</i> lagi. .

## System Call
![System call](https://linux-kernel-labs.github.io/refs/heads/master/_images/ditaa-48374873962ca32ada36c14ab9a83b60f112a1e0.png)
Setiap aplikasi akan selalu mengakses *kernel mode* sehingga perlu suatu *handler* untuk menangani perubahan hak akses dari *user mode* ke *kernel mode*. Pada linux, dikenal dengan system call/syscall yang membuat proses pergantian hak akses tersebut terjadi. Ketika *user* menggunakan syscall maka akan ada perubahan *privileged* menjadi *kernel mode*. Jika menggunakan mekanisme pada pengembangan web, syscall mirip sekali dengan *API* (*Application Programming Interface*) yang menjadi perantara antara *user* dengan server. 

Pada linux, syscall dideklarasikan berdasarkan urutan angka, sehingga ketika kita ingin menggunakan syscall, kita hanya akan mengakses nomor syscall yang akan digunakan saja. Perlu diperhatikan juga, linux mendukung banyak sekali arsitektur komputer dan setiap arsitektur komputer memiliki angka syscall yang berbeda (seperti pada arsitektur x86 dengan x86_64). Nomor syscall bisa dilihat pada `/usr/include/x86_64-linux-gnu/asm/unistd_64.h` untuk arsitektur x86_64, atau `/usr/include/x86_64-linux-gnu/asm/unistd_32.h` untuk arsitektur x86. Setiap fungsi syscall terdapat *handler* untuk disambungkan dengan nomor syscall. Contohnya pada syscall write, berada pada nomor 1, dengan handler sys_write. 
```
#define __NR_read 0
#define __NR_write 1
#define __NR_open 2
#define __NR_close 3
#define __NR_stat 4
#define __NR_fstat 5
#define __NR_lstat 6
#define __NR_poll 7
#define __NR_lseek 8
#define __NR_mmap 9
#define __NR_mprotect 10
#define __NR_munmap 11
#define __NR_brk 12
#define __NR_rt_sigaction 13
#define __NR_rt_sigprocmask 14
#define __NR_rt_sigreturn 15
...
```

### Register Arguments
Setiap syscall memiliki aturan penggunaan yang berbeda-beda yang diimplementasikan pada parameter. Aturan ini dituliskan pada [entry](https://elixir.bootlin.com/linux/v6.10/source/arch/x86/entry/entry_64.S) linux source code.
```
 * Registers on entry:
 * rax  system call number
 * rcx  return address
 * r11  saved rflags (note: r11 is callee-clobbered register in C ABI)
 * rdi  arg0
 * rsi  arg1
 * rdx  arg2
 * r10  arg3 (needs to be moved to rcx to conform to C ABI)
 * r8   arg4
 * r9   arg5
```	
Nomor syscall yang akan digunakan harus dimasukkan ke dalam register rax, kemudian diikuti parameter lain yang secara berurutan dimasukkan ke dalam register rdi, rsi, rdx, dan seterusnya. Untuk melihat parameter fungsi-fungsi syscall, bisa gunakan perintah `man 2` dan diikuti nama fungsi syscallnya, contohnya ketika ingin mengetahui parameter apa yang dibutuhkan pada write , bisa gunakan `man 2 write`
```
write(2)                   System Calls Manual

NAME
       write - write to a file descriptor

LIBRARY
       Standard C library (libc, -lc)

SYNOPSIS
       #include <unistd.h>

       ssize_t write(int fd, const void buf[.count], size_t count);

```
Pada fungsi write, dibutuhkan tiga parameter

`ssize_t write(int fd, const void buf[.count], size_t count);`

- rdi harus berisi fd (file descriptor)
- rsi harus berisi buffer
- rdx harus berisi ukuran buffer dari rsi

Selain menggunakan perintah `man`, bisa gunakan website [ini](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md) untuk mengetahui parameter yang harus digunakan suatu syscall.

### Penggunaan Syscall pada C
Kita bisa lakukan percobaan untuk menggunakan syscall dengan bahasa pemrograman C, hal ini bisa terjadi karena pada libc terdapat fungsi `syscall` untuk mengakses syscall pada linux.
```c
#include <unistd.h>
#include <sys/syscall.h>

int main(void){
	syscall(SYS_write, 1, "Hello, World!\n", 14);
}
```
Kita bisa memahami fungsi syscall tersebut dengan melihat isi fungsi `syscall` pada [glibc](https://github.com/lattera/glibc/blob/master/sysdeps/unix/sysv/linux/x86_64/syscall.S).
```
	.text
ENTRY (syscall)
	movq %rdi, %rax		/* Syscall number -> rax.  */
	movq %rsi, %rdi		/* shift arg1 - arg5.  */
	movq %rdx, %rsi
	movq %rcx, %rdx
	movq %r8, %r10
	movq %r9, %r8
	movq 8(%rsp),%r9	/* arg6 is on the stack.  */
	syscall			/* Do the system call.  */
	cmpq $-4095, %rax	/* Check %rax for error.  */
	jae SYSCALL_ERROR_LABEL	/* Jump to error handler if error.  */
	ret			/* Return to caller.  */

PSEUDO_END (syscall)
```
Fungsi `syscall` pada libc tersebut mengikuti aturan x86_64 ABI sesuai dengan aturan penggunaannya. Setiap argument yang digunakan pada fungsi `syscall` di C akan dimasukkan ke dalam register-register yang telah ditetapkan oleh linux. SYS_write akan bernilai satu karena pada angka syscall di arsitektur x86_64 bernilai satu, kemudian diikuti register rdi, rsi, dan rdx.

### Penggunaan Syscall pada Assembly
Syscall juga dapat diimplementasikan pada assembly. Saya membuat file assembly x86_64 sederhana yang menggunakan syscall *write* untuk mencetak *string* ke layar.
```
; test.S

.section .text
.global _start
_start:
	movq $1, %rax
	movq $1, %rdi
	movq $msg, %rsi
	movq $14, %rdx
	syscall

	movq $60, %rax
	movq $0, %rdi
	syscall

.section .data
msg: .string "Hello, World!\n"
```
Kita *compile* dengan gcc menggunakan argument static agar file binary-nya menjadi statically linked (tidak menggunakan dynamic library).

`gcc -static -nostartfiles test.S -o test`

Kita bisa cek *syscall* apa saja yang digunakan dalam menjalankan program tersebut menggunakan *strace*.
```bash
$ strace ./test
execve("./test", ["./test"], 0x7ffdfe6d5150 /* 47 vars */) = 0
write(1, "Hello, World!\n", 14Hello, World!
)         = 14
exit(0)                                 = ?
+++ exited with 0 +++

```
Dapat kita lihat bahwa syscall yang digunakan adalah syscall *write* dan *exit*.


## Penulisan Syscall Pada Linux
Setiap syscall didefinisikan pada setiap folder di *kernel source code* sesuai fungsi masing-masing. Misalnya pada syscall *read*, berada pada folder `fs/read_write.c`.
```c
SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
	return ksys_read(fd, buf, count);
}
```
Setiap syscall dituliskan menggunakan fungsi `SYSCALL_DEFINE`, lalu isi dari fungsi syscall tersebut akan masuk ke fungsi ksys yang berisi *source code* proses *read* berlangsung. Angka tiga pada `SYSCALL_DEFINE` menandakan jumlah parameter yang digunakan syscall tersebut.
```c
ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

	if (f.file) {
		loff_t pos, *ppos = file_ppos(f.file);
		if (ppos) {
			pos = *ppos;
			ppos = &pos;
		}
		ret = vfs_read(f.file, buf, count, ppos);
		if (ret >= 0 && ppos)
			f.file->f_pos = pos;
		fdput_pos(f);
	}
	return ret;
}
```

Ketika komputer booting pertama kali, kernel akan menginisialisasi syscall *handler* yang disimpan pada register MSR_LSTAR. Untuk mengatur register MSR_LSTAR, digunakan fungsi wrmsrl, yang memasukkan alamat dari entry point untuk syscall x86_64.
```
wrmsrl(MSR_LSTAR, (unsigned long)entry_SYSCALL_64);
```
Instruksi syscall akan digunakan sebagai *trap* ke *kernel mode* untuk melakukan syscall, kemudian CPU akan memeriksa isi dari register MSR_LSTAR yang didalamnya terdapat alamat syscall handler (*entry_SYSCALL_64*). *Entry point* akan menyimpan nilai-nilai register yang digunakan sebagai syscall *number* dan parameter-parameter syscall ke dalam *stack* pada *kernel mode*. Setelah itu akan masuk ke dalam syscall dispatcher [do_syscall_64](https://elixir.bootlin.com/linux/v6.10/source/arch/x86/entry/common.c#L76) untuk memeriksa syscall *number* dan parameter yang digunakan, misalnya, ketika menggunakan syscall *number* 1, maka dari syscall dispatcher tersebut akan langsung mengarah ke fungsi kernel untuk *write*. Nilai register rax akan dimasukkan ke dalam *stack* (struct pt_regs) diikuti oleh alamat dari semua parameter yang digunakan, setelah semuanya diolah, maka outputnya akan disimpan pada rax. Dan akan berpindah lagi menjadi *user mode* dengan instruksi SYSRET/IRET
```
SYM_INNER_LABEL(entry_SYSCALL_64_after_hwframe, SYM_L_GLOBAL)
	pushq	%rax					/* pt_regs->orig_ax */

	PUSH_AND_CLEAR_REGS rax=$-ENOSYS

	/* IRQs are off. */
	movq	%rsp, %rdi
	/* Sign extend the lower 32bit as syscall numbers are treated as int */
	movslq	%eax, %rsi

	/* clobbers %rax, make sure it is after saving the syscall nr */
	IBRS_ENTER
	UNTRAIN_RET
	CLEAR_BRANCH_HISTORY

	call	do_syscall_64		/* returns with IRQs disabled */
```



## Referensi
[Linux v6.10 Source Code](https://elixir.bootlin.com/linux/v6.10/source)


[Linux kernel labs](https://linux-kernel-labs.github.io/refs/heads/master/index.html)


[The Definitive Guide to Linux System Calls](https://blog.packagecloud.io/the-definitive-guide-to-linux-system-calls/)


[Linux Inside: System Calls](https://0xax.gitbooks.io/linux-insides/content/)

[System V ABI x86_64](https://gitlab.com/x86-psABIs/x86-64-ABI)

[Linux System Call Table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md)