/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARGUS_CREDFILE_H
#define ARGUS_CREDFILE_H

/*
 * Shared between the credential-read sensor (edr.bpf.c) and the file_open
 * enforcement hook (edr_lsm.bpf.c): the cheap basename test that recognises the
 * shadow password files without walking the full path. Both objects match the
 * same files, so the predicate lives here rather than being duplicated.
 */

/* True only for the exact NUL-terminated basenames "shadow" and "gshadow". */
static __always_inline int is_shadow_basename(const char *base)
{
    if (base[0] == 's' && base[1] == 'h' && base[2] == 'a' && base[3] == 'd' &&
        base[4] == 'o' && base[5] == 'w' && base[6] == 0)
        return 1; /* shadow */
    if (base[0] == 'g' && base[1] == 's' && base[2] == 'h' && base[3] == 'a' &&
        base[4] == 'd' && base[5] == 'o' && base[6] == 'w' && base[7] == 0)
        return 1; /* gshadow */
    return 0;
}

#endif /* ARGUS_CREDFILE_H */
