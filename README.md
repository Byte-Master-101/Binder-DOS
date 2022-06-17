# Security Report - BUG_ON in Android 10.0.0 Binder Reachable From User-Mode

## Bug Trigger POC
I worked on a reliable POC that causes a `BUG_ON` to be called in the kernel from a user-mode process.
The `BUG_ON` was reached by making a `BINDER_WRITE_READ` `ioctl` call with a transaction containing the following:
 1. An arbitrary interface CString
 1. A parent `binder_buffer_object`
 2. A child `binder_buffer_object` with a parent_offset that is not divisible by 4

A visual representation of the transaction is included as an attachment (`Transaction.png`).

As far as I know, binder IPC calls can be made from the browser sandbox, so this can theoretically be used for remote denial of
service if the user opens a malicious URL.

#### Compiling The POC Using NDK
To build the code using the NDK, extract the ZIP file named `dos_ndk.zip` to a path of your choice.
Then, run this command in the folder where the `Makefile` is located:
```
NDK_ROOT=~/path/to/Android/Sdk/ndk/xx.x.xxxxxx make build
```
This is an example that builds the code, pushes it to a device through ADB and runs it on the target device (that uses my version of NDK):
```
NDK_ROOT=~/Android/Sdk/ndk/22.0.7026061 make build push run
```
To change the target architecture of the build, you can edit the `ARCH` variable in the included `Makefile`.

#### Compiling The POC Using AOSP Build System
To build the code using the AOSP build system, extract the ZIP file named `dos_aosp.zip` to your `Your-AOSP-Root/external` directory.
The `Android.bp` file should now be located it `Your-AOSP-Root/external/dos/Android.bp`. After extracting, perform these steps:
```
cd Your-AOSP-Root
source build/envsetup.sh
lunch # Choose your build target
mmm external/dos -j`nproc`
```

After the `mmm` command is done, the location of the build will be displayed. You can then push and run the build on the target device.

## Bug Backtrace Log
### Bug Backtrace From The AOSP Cuttlefish build
This bug was initially triggered on an unmodified Cuttlefish build of [AOSP's `android-security-10.0.0_r55` branch](https://android.googlesource.com/platform/manifest/+/refs/heads/android-security-10.0.0_r55),
which has the following fingerprint:
```
$ adb shell getprop ro.build.fingerprint
generic/aosp_cf_x86_phone/vsoc_x86:10/QSV1.210329.008/eng.mohame.20210622.201855:userdebug/test-keyskeys
$ adb shell cat /proc/version
Linux version 4.14.123-420850-g3b491d485e67 (android-build@abfarm-us-west1-c-0053) (Android (5484270 based on r353983c) clang version 9.0.3 (https://android.googlesource.com/toolchain/clang 745b335211bb9eadfa6aa6301f84715cee4b37c5) (https://android.googlesource.com/toolchain/llvm 60cf23e54e46c807513f7a36d0a7b777920b5881) (based on LLVM 9.0.3svn)) #1 SMP PREEMPT Fri Jun 7 02:56:45 UTC 2019
```

Running the POC produces the following output:
```
$ adb shell /data/local/tmp/dos
Preparing transaction...
RAW transaction data: 41 42 43 00 85 2a 74 70 00 00 00 00 70 3c c5 ff 00 00 00 00 64 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 85 2a 74 70 01 00 00 00 70 3c c5 ff 00 00 00 00 64 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 32 00 00 00 00 00 00 00
Sending transaction...
```

The raw `BUG_ON` backtrace generated from this build is:
```
[ 2350.028593] kernel BUG at /buildbot/src/partner-android/q-common-android-4.14/common/drivers/android/binder_alloc.c:1128!
[ 2350.032746] invalid opcode: 0000 [#1] PREEMPT SMP PTI
[ 2350.034529] Modules linked in:
[ 2350.035515] CPU: 1 PID: 4078 Comm: dos Not tainted 4.14.123-420850-g3b491d485e67 #1
[ 2350.037927] task: 00000000ea8f17b6 task.stack: 00000000ddd0dcc8
[ 2350.039853] RIP: 0010:binder_alloc_do_buffer_copy+0x178/0x180
[ 2350.041846] RSP: 0018:ffffc900035cfaa8 EFLAGS: 00210202
[ 2350.043631] RAX: 00000000ec369000 RBX: 0000000000000004 RCX: 000000000000009a
[ 2350.046017] RDX: ffff88807c817f60 RSI: 0000000000000148 RDI: ffff88807b9689a0
[ 2350.048459] RBP: ffffc900035cfaf8 R08: ffffc900035cfc18 R09: 0000000000000008
[ 2350.051677] R10: 0000000000000000 R11: ffffffff813dc200 R12: ffff88807c817f60
[ 2350.054913] R13: ffff88807b9689a0 R14: 0000000000000004 R15: 0000000000000064
[ 2350.058037] FS:  0000000000000000(0000) GS:ffff88807fd00000(006b) knlGS:00000000f237d494
[ 2350.061533] CS:  0010 DS: 002b ES: 002b CR0: 0000000080050033
[ 2350.063933] CR2: 00000000e89ae700 CR3: 000000002013a006 CR4: 00000000003606e0
[ 2350.066829] Call Trace:
[ 2350.067822]  binder_alloc_copy_to_buffer+0x1a/0x20
[ 2350.069891]  binder_transaction+0x2c9d/0x3930
[ 2350.071543]  ? mntput+0x1b/0x30
[ 2350.072882]  ? terminate_walk+0x6f/0x110
[ 2350.074713]  binder_ioctl_write_read+0x5f0/0x3ae0
[ 2350.076666]  ? avc_has_extended_perms+0x311/0x480
[ 2350.078558]  ? binder_get_thread+0x294/0x2b0
[ 2350.080404]  binder_ioctl+0x221/0x730
[ 2350.081874]  compat_SyS_ioctl+0x139/0x15f0
[ 2350.083585]  do_fast_syscall_32+0xa2/0x100
[ 2350.085319]  entry_SYSENTER_compat+0x7f/0x8e
[ 2350.087138] RIP: 0023:0xf24c9ec9
[ 2350.088337] RSP: 002b:00000000ffa57d2c EFLAGS: 00200286 ORIG_RAX: 0000000000000036
[ 2350.090650] RAX: ffffffffffffffda RBX: 0000000000000003 RCX: 00000000c0306201
[ 2350.092822] RDX: 00000000ffa57db0 RSI: 00000000f1ca7140 RDI: 00000000ffa57e78
[ 2350.095108] RBP: 00000000ffa57d78 R08: 0000000000000000 R09: 0000000000000000
[ 2350.097324] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
[ 2350.099480] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[ 2350.101675] Code: 4d b0 4d 29 e1 48 8b 4d b8 48 8b 7d c0 0f 85 30 ff ff ff eb 07 e8 bf 76 89 ff eb e2 48 83 c4 28 5b 41 5c 41 5d 41 5e 41 5f 5d c3 <0f> 0b 66 0f 1f 44 00 00 55 48 89 e5 4d 89 c1 49 89 f0 31 f6 e8 
[ 2350.108778] RIP: binder_alloc_do_buffer_copy+0x178/0x180 RSP: ffffc900035cfaa8
[ 2350.114861] ---[ end trace 0132b95adaf66f79 ]---
```

### Symbolized Bug Backtrace
In order to get a symbolized backtrace, I built the [`ASB-2021-06-05_4.14-q-release` tag of the common kernel](https://android.googlesource.com/kernel/common/+/refs/tags/ASB-2021-06-05_4.14-q-release)
with debug info, and re-ran the exploit. The fingerprint of the device with the new kernel is:
```
$ adb shell getprop ro.build.fingerprint
generic/aosp_cf_x86_phone/vsoc_x86:10/QSV1.210329.008/eng.mohame.20210622.201855:userdebug/test-keys
$ adb shell cat /proc/version
Linux version 4.14.142 (mohamed@mohamed-G5-5590) (gcc version 8.4.0 (Ubuntu 8.4.0-3ubuntu2)) #57 SMP PREEMPT Wed Jun 23 05:21:15 EET 2021
```

The raw `BUG_ON` backtrace generated from this build is:
```
[  130.026773] kernel BUG at drivers/android/binder_alloc.c:1128!
[  130.027380] invalid opcode: 0000 [#1] PREEMPT SMP PTI
[  130.027902] Modules linked in:
[  130.028226] CPU: 1 PID: 2899 Comm: dos Not tainted 4.14.142 #57
[  130.028842] task: 00000000b1d80bb7 task.stack: 0000000039b0926d
[  130.029468] RIP: 0010:binder_alloc_do_buffer_copy+0x49/0x190
[  130.030096] RSP: 0018:ffffc90001c07b78 EFLAGS: 00210202
[  130.030636] RAX: 00000000e8f14000 RBX: ffff88807b88f000 RCX: ffff88807b88f1d8
[  130.031369] RDX: 0000000000000140 RSI: 0000000000000001 RDI: ffff88807b88f1a0
[  130.032101] RBP: ffffc90001c07bc0 R08: ffffc90001c07cc0 R09: 0000000000000008
[  130.032830] R10: ffffea00007c6440 R11: ffff88807ba41670 R12: 0000000000000008
[  130.033563] R13: 000000000000009a R14: ffffc90001c07cc0 R15: ffff88807ba41660
[  130.034386] FS:  0000000000000000(0000) GS:ffff88807fd00000(006b) knlGS:00000000f4457494
[  130.035211] CS:  0010 DS: 002b ES: 002b CR0: 0000000080050033
[  130.035798] CR2: 00000000f3a22000 CR3: 000000002f308001 CR4: 00000000003606e0
[  130.036529] Call Trace:
[  130.036794]  ? binder_validate_ptr+0x5f/0xa0
[  130.037240]  binder_alloc_copy_to_buffer+0x1e/0x20
[  130.037739]  binder_transaction+0x1621/0x22b0
[  130.038249]  binder_thread_write+0x511/0xf00
[  130.038698]  ? do_filp_open+0xa6/0x100
[  130.039091]  binder_ioctl+0x693/0x896
[  130.039476]  compat_SyS_ioctl+0xcc/0x1460
[  130.039894]  ? __audit_syscall_exit+0x22a/0x2a0
[  130.040482]  do_fast_syscall_32+0xad/0x1fa
[  130.040914]  entry_SYSENTER_compat+0x7f/0x8e
[  130.041374] RIP: 0023:0xf45a3c89
[  130.041722] RSP: 002b:00000000ffc53abc EFLAGS: 00200282 ORIG_RAX: 0000000000000036
[  130.042557] RAX: ffffffffffffffda RBX: 0000000000000003 RCX: 00000000c0306201
[  130.043303] RDX: 00000000ffc53b40 RSI: 00000000f412f140 RDI: 00000000ffc53c08
[  130.044050] RBP: 00000000ffc53b08 R08: 0000000000000000 R09: 0000000000000000
[  130.044800] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
[  130.045626] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[  130.046465] Code: 83 ec 20 48 89 55 c0 48 8b 12 48 89 7d c8 48 8b 40 58 40 88 75 bf 48 39 ca 0f 84 19 01 00 00 48 8b 52 58 48 29 c2 49 39 d4 76 02 <0f> 0b 4c 29 e2 49 39 d5 77 f6 41 f6 c5 03 75 f0 48 8b 75 c0 0f 
[  130.048440] RIP: binder_alloc_do_buffer_copy+0x49/0x190 RSP: ffffc90001c07b78
[  130.050235] ---[ end trace d7fdc2d74fd58912 ]---
```

I symbolized it, so now it we have a clear backtrace to follow:
```
kernel BUG at drivers/android/binder_alloc.c:1128!
invalid opcode: 0000 [#1] PREEMPT SMP PTI
Modules linked in:
CPU: 1 PID: 2899 Comm: dos Not tainted 4.14.142 #57
task: 00000000b1d80bb7 task.stack: 0000000039b0926d
RIP: 0010:check_buffer drivers/android/binder_alloc.c:1037
RIP: 0010:binder_alloc_do_buffer_copy+0x49/0x190 drivers/android/binder_alloc.c:1128
RSP: 0018:ffffc90001c07b78 EFLAGS: 00210202
RAX: 00000000e8f14000 RBX: ffff88807b88f000 RCX: ffff88807b88f1d8
RDX: 0000000000000140 RSI: 0000000000000001 RDI: ffff88807b88f1a0
RBP: ffffc90001c07bc0 R08: ffffc90001c07cc0 R09: 0000000000000008
R10: ffffea00007c6440 R11: ffff88807ba41670 R12: 0000000000000008
R13: 000000000000009a R14: ffffc90001c07cc0 R15: ffff88807ba41660
FS:  0000000000000000(0000) GS:ffff88807fd00000(006b) knlGS:00000000f4457494
CS:  0010 DS: 002b ES: 002b CR0: 0000000080050033
CR2: 00000000f3a22000 CR3: 000000002f308001 CR4: 00000000003606e0
Call Trace:
 binder_alloc_copy_to_buffer+0x1e/0x20 drivers/android/binder_alloc.c:1164
 binder_fixup_parent drivers/android/binder.c:2851
 binder_transaction+0x1621/0x22b0 drivers/android/binder.c:3486
 binder_thread_write+0x511/0xf00 drivers/android/binder.c:3875
 binder_ioctl_write_read drivers/android/binder.c:4829
 binder_ioctl+0x693/0x896 drivers/android/binder.c:5006
 C_SYSC_ioctl fs/compat_ioctl.c:1591
 compat_SyS_ioctl+0xcc/0x1460 fs/compat_ioctl.c:1538
 do_syscall_32_irqs_on arch/x86/entry/common.c:335
 do_fast_syscall_32+0xad/0x1fa arch/x86/entry/common.c:397
 entry_SYSENTER_compat+0x7f/0x8e arch/x86/entry/entry_64_compat.S:139
RIP: 0023:0xf45a3c89
RSP: 002b:00000000ffc53abc EFLAGS: 00200282 ORIG_RAX: 0000000000000036
RAX: ffffffffffffffda RBX: 0000000000000003 RCX: 00000000c0306201
RDX: 00000000ffc53b40 RSI: 00000000f412f140 RDI: 00000000ffc53c08
RBP: 00000000ffc53b08 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
Code: 83 ec 20 48 89 55 c0 48 8b 12 48 89 7d c8 48 8b 40 58 40 88 75 bf 48 39 ca 0f 84 19 01 00 00 48 8b 52 58 48 29 c2 49 39 d4 76 02 <0f> 0b 4c 29 e2 49 39 d5 77 f6 41 f6 c5 03 75 f0 48 8b 75 c0 0f
RIP: binder_alloc_do_buffer_copy+0x49/0x190 RSP: ffffc90001c07b78
---[ end trace d7fdc2d74fd58912 ]---
```

## Bug Analysis
From now on, any URLs linked will point to the [`ASB-2021-06-05_4.14-q-release` tag of the common kernel](https://android.googlesource.com/kernel/common/+/refs/tags/ASB-2021-06-05_4.14-q-release).

The main line in the POC that causes the `BUG_ON` is this line in `dos.c`:
```c
childObj->parent_offset = 50;  // Must be not divisible by sizeof(u32) for the crash to happen
```
If `parent_offset` was set to a value that is divisible by `sizeof(u32)` (e.g., 52, 40), the `BUG_ON` would not be triggered.

The `BUG_ON` that is triggered is in [`binder_alloc_do_buffer_copy` in binder_alloc.c](https://android.googlesource.com/kernel/common/+/refs/tags/ASB-2021-06-05_4.14-q-release/drivers/android/binder_alloc.c#1128).
The important part of the backtrace is:
1. [`binder_alloc_copy_to_buffer` binder_alloc.c:1164](https://android.googlesource.com/kernel/common/+/refs/tags/ASB-2021-06-05_4.14-q-release/drivers/android/binder_alloc.c#1164)
1. [`binder_fixup_parent` binder.c:2851](https://android.googlesource.com/kernel/common/+/refs/tags/ASB-2021-06-05_4.14-q-release/drivers/android/binder.c#2851)
1. [`binder_transaction` binder.c:3486](https://android.googlesource.com/kernel/common/+/refs/tags/ASB-2021-06-05_4.14-q-release/drivers/android/binder.c#3486)
1. [`binder_thread_write` binder.c:3875](https://android.googlesource.com/kernel/common/+/refs/tags/ASB-2021-06-05_4.14-q-release/drivers/android/binder.c#3875)
1. [`binder_ioctl_write_read` binder.c:4829](https://android.googlesource.com/kernel/common/+/refs/tags/ASB-2021-06-05_4.14-q-release/drivers/android/binder.c#4829)

During the fixup of the second `binder_buffer_object`, the `buffer_offset` is calculated in [`binder_fixup_parent` directly before calling `binder_alloc_copy_to_buffer`](https://android.googlesource.com/kernel/common/+/refs/tags/ASB-2021-06-05_4.14-q-release/drivers/android/binder.c#2849).
The calculation does not check beforehand if the value of `bp->parent_offset` (which is user defined) is byte-aligned with `sizeof(u32)`.
In the case of our transaction's fixup, the `buffer_offset` would equal `154`.
This value is directly passed through these functions with no further checks:
 1. `binder_alloc_copy_to_buffer`
 1. `binder_alloc_do_buffer_copy`
 1. `check_buffer`

The `check_buffer` function then [checks if the value of the offset is byte-aligned with `sizeof(u32)`](https://android.googlesource.com/kernel/common/+/refs/tags/ASB-2021-06-05_4.14-q-release/drivers/android/binder_alloc.c#1036).
This check returns `false` (in our case) because `buffer_offset` (`154`) is not byte-aligned with `sizeof(u32)`. The result of the `check_buffer` function call is directly
passed to a `BUG_ON`, which is the cause of the crash.

#### Vulnerable Kernel Versions
I checked all the latest Android Security Bulletin tags in the [common kernel tree](https://android.googlesource.com/kernel/common/), and (through static code analysis)
it seems that the following kernel versions are still vulnerable:
- ASB-2021-06-05_4.19-q-release
- ASB-2021-06-05_4.19-q
- ASB-2021-06-05_4.19-stable
- ASB-2021-06-05_4.14-q-release
- ASB-2021-06-05_4.14-q
- ASB-2021-06-05_4.14-stable
- ASB-2021-06-05_4.9-q-release
- ASB-2021-06-05_4.9-q

While these kernel versions are not vulnerable:
- ASB-2021-06-05_13-5.10
- ASB-2021-06-05_mainline
- ASB-2021-06-05_12-5.10
- ASB-2021-06-05_12-5.4
- ASB-2021-06-05_11-5.4
- ASB-2021-06-05_4.14-p-release
- ASB-2021-06-05_4.14-p
- ASB-2021-06-05_4.9-p-release
- ASB-2021-06-05_4.9-o-mr1
- ASB-2021-06-05_4.9-p
- ASB-2021-06-05_4.9-o
- ASB-2021-06-05_4.4-p-release
- ASB-2021-06-05_4.4-o-mr1
- ASB-2021-06-05_4.4-p
- ASB-2021-06-05_4.4-o

## Kernel Code Patch
A small code change that fixes the bug would be to return `-EINVAL` in case `parent_offset` is not byte-aligned with
`sizeof(u32)`, which forces the user to make fixups that are byte-aligned with `sizeof(u32)`. [This is similar to the
way it is done in some of the non-vulnerable versions of the kernel](https://android.googlesource.com/kernel/common/+/refs/tags/ASB-2021-06-05_13-5.10/drivers/android/binder_alloc.c#1240).
This would make the [`binder_fixup_parent` function in the `ASB-2021-06-05_4.14-q-release` branch](https://android.googlesource.com/kernel/common/+/refs/tags/ASB-2021-06-05_4.14-q-release/drivers/android/binder.c#2805)
look like this:
```c
static int binder_fixup_parent(struct binder_transaction *t,
			       struct binder_thread *thread,
			       struct binder_buffer_object *bp,
			       binder_size_t off_start_offset,
			       binder_size_t num_valid,
			       binder_size_t last_fixup_obj_off,
			       binder_size_t last_fixup_min_off)
{
    [...]

    if (parent->length < sizeof(binder_uintptr_t) ||
        bp->parent_offset > parent->length - sizeof(binder_uintptr_t) ||
        !IS_ALIGNED(bp->parent_offset, sizeof(u32))) {
            /* Either no space for a pointer, or the pointer is not aligned with sizeof(u32). */
            binder_user_error("%d:%d got transaction with invalid parent offset\n",
            proc->pid, thread->pid);
            return -EINVAL;
    }
    buffer_offset = bp->parent_offset +
    (uintptr_t)parent->buffer - (uintptr_t)b->user_data;
    binder_alloc_copy_to_buffer(&target_proc->alloc, b, buffer_offset,
    &bp->buffer, sizeof(bp->buffer));
    
    return 0;
}
```

Attached is a zip file called `patches.zip`, which contains a patch file (generated using `git diff`) for the
latest ASB tag for each of the vulnerable branches. I tested the patch on one of the branches then copied the changes
to all the other branches.

This is the output of the POC after applying the patch:
```
$ adb shell /data/local/tmp/dos
Preparing transaction...
RAW transaction data: 41 42 43 00 85 2a 74 70 00 00 00 00 80 48 3f a8 fe 7f 00 00 64 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 85 2a 74 70 01 00 00 00 80 48 3f a8 fe 7f 00 00 64 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 32 00 00 00 00 00 00 00
Sending transaction...
BUG_ON was not triggered!
```
## Personal Information
 - Name: Mohammed Mokhtar Abdelrasoul
 - Email: mokhtar.mohammed.red@gmail.com
