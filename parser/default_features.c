/*
 * This file contains a set of old feature files that are used under different
 * circumstances.
 *
 * match_n_abi: feature abi for oldest match_file (pre features) abi.
 *
 * match_c_abi: features abi for match_file (pre features) abi that supports
 *              create.
 *
 * match_cn_abi: features abi for match_file (pre features) abi that supports
 *               create and network.
 *
 * default_features_abi: is the feature abi used when policy is not tagged
 *                       with an abi and no featuere-abi was specified to the
 *                       parser.
 */

#include "parser.h"


const char *match_n_abi =
  "caps {mask {chown dac_override dac_read_search fowner fsetid kill setgid setuid setpcap linux_immutable net_bind_service net_broadcast net_admin net_raw ipc_lock ipc_owner sys_module sys_rawio sys_chroot sys_ptrace sys_pacct sys_admin sys_boot sys_nice sys_resource sys_time sys_tty_config mknod lease audit_write audit_control setfcap mac_override mac_admin syslog wake_alarm block_suspend audit_read\
}\
}\
rlimit {mask {cpu fsize data stack core rss nproc nofile memlock as locks sigpending msgqueue nice rtprio rttime\
}\
}\
capability {0xffffff\
}\
network {af_unix {yes\
}\
af_mask {unspec unix inet ax25 ipx appletalk netrom bridge atmpvc x25 inet6 rose netbeui security key netlink packet ash econet atmsvc rds sna irda pppox wanpipe llc ib mpls can tipc bluetooth iucv rxrpc isdn phonet ieee802154 caif alg nfc vsock kcm qipcrtr smc xdp\
}\
}\
file {mask {read write exec append mmap_exec link lock\
}\
}\
domain {change_profile {yes\
}\
change_onexec {yes\
}\
change_hatv {yes\
}\
change_hat {yes\
}\
}\
policy {\
v6 {yes\
}\
v5 {yes\
}\
}\
}\
";


/****************************** match_c_abi *******************************/
const char *match_c_abi =
"caps {mask {chown dac_override dac_read_search fowner fsetid kill setgid setuid setpcap linux_immutable net_bind_service net_broadcast net_admin net_raw ipc_lock ipc_owner sys_module sys_rawio sys_chroot sys_ptrace sys_pacct sys_admin sys_boot sys_nice sys_resource sys_time sys_tty_config mknod lease audit_write audit_control setfcap mac_override mac_admin syslog wake_alarm block_suspend audit_read\
}\
}\
rlimit {mask {cpu fsize data stack core rss nproc nofile memlock as locks sigpending msgqueue nice rtprio rttime\
}\
}\
capability {0xffffff\
}\
file {mask {create read write exec append mmap_exec link lock\
}\
}\
domain {change_profile {yes\
}\
change_onexec {yes\
}\
change_hatv {yes\
}\
change_hat {yes\
}\
}\
policy {\
v6 {yes\
}\
v5 {yes\
}\
}\
}\
";

/****************************** match_cn_abi ******************************/
const char *match_cn_abi =
"caps {mask {chown dac_override dac_read_search fowner fsetid kill setgid setuid setpcap linux_immutable net_bind_service net_broadcast net_admin net_raw ipc_lock ipc_owner sys_module sys_rawio sys_chroot sys_ptrace sys_pacct sys_admin sys_boot sys_nice sys_resource sys_time sys_tty_config mknod lease audit_write audit_control setfcap mac_override mac_admin syslog wake_alarm block_suspend audit_read\
}\
}\
rlimit {mask {cpu fsize data stack core rss nproc nofile memlock as locks sigpending msgqueue nice rtprio rttime\
}\
}\
capability {0xffffff\
}\
network {af_unix {yes\
}\
af_mask {unspec unix inet ax25 ipx appletalk netrom bridge atmpvc x25 inet6 rose netbeui security key netlink packet ash econet atmsvc rds sna irda pppox wanpipe llc ib mpls can tipc bluetooth iucv rxrpc isdn phonet ieee802154 caif alg nfc vsock kcm qipcrtr smc xdp\
}\
}\
file {mask {create read write exec append mmap_exec link lock\
}\
}\
domain {change_profile {yes\
}\
change_onexec {yes\
}\
change_hatv {yes\
}\
change_hat {yes\
}\
}\
policy {\
v6 {yes\
}\
v5 {yes\
}\
}\
}\
";


/************************** deafult_features_abi ***************************/

const char *default_features_abi =
"query {label {multi_transaction {yes\
}\
data {yes\
}\
perms {allow deny audit quiet\
}\
}\
}\
dbus {mask {acquire send receive\
}\
}\
signal {mask {hup int quit ill trap abrt bus fpe kill usr1 segv usr2 pipe alrm term stkflt chld cont stop stp ttin ttou urg xcpu xfsz vtalrm prof winch io pwr sys emt lost\
}\
}\
ptrace {mask {read trace\
}\
}\
caps {mask {chown dac_override dac_read_search fowner fsetid kill setgid setuid setpcap linux_immutable net_bind_service net_broadcast net_admin net_raw ipc_lock ipc_owner sys_module sys_rawio sys_chroot sys_ptrace sys_pacct sys_admin sys_boot sys_nice sys_resource sys_time sys_tty_config mknod lease audit_write audit_control setfcap mac_override mac_admin syslog wake_alarm block_suspend audit_read perfmon bpf\
}\
}\
rlimit {mask {cpu fsize data stack core rss nproc nofile memlock as locks sigpending msgqueue nice rtprio rttime\
}\
}\
capability {0xffffff\
}\
namespaces {pivot_root {no\
}\
profile {yes\
}\
}\
mount {mask {mount umount pivot_root\
}\
}\
network {af_unix {yes\
}\
af_mask {unspec unix inet ax25 ipx appletalk netrom bridge atmpvc x25 inet6 rose netbeui security key netlink packet ash econet atmsvc rds sna irda pppox wanpipe llc ib mpls can tipc bluetooth iucv rxrpc isdn phonet ieee802154 caif alg nfc vsock kcm qipcrtr smc xdp\
}\
}\
file {mask {create read write exec append mmap_exec link lock\
}\
}\
domain {version {1.2\
}\
}\
computed_longest_left {yes\
}\
post_nnp_subset {yes\
}\
fix_binfmt_elf_mmap {yes\
}\
stack {yes\
}\
change_profile {yes\
}\
change_onexec {yes\
}\
change_hatv {yes\
}\
change_hat {yes\
}\
}\
policy {set_load {yes\
}\
versions {v8 {yes\
}\
v7 {yes\
}\
v6 {yes\
}\
v5 {yes\
}\
}\
}\
";
