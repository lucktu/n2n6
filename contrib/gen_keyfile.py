#!/usr/bin/env python

# (c) 2009 Richard Andrews <andrews@ntop.org>

# Program to generate a n2n_edge key schedule file for twofish keys
# Each key line consists of the following element
# <from> <until> <txfrm> <opaque>
#
# where <from>, <until> are UNIX time_t values of key valid period
#       <txfrm> is the transform ID (=2 for twofish)
#       <opaque> is twofish-specific data as follows
# <sec_id>_<hex_key>

import os
import sys
import time
import secrets

# a year worth of keys
NUM_KEYS = 365 * 10
# a is valid for one day
KEY_LIFE = 60 * 60 * 24
KEY_LEN = 32

now = time.time()
start_sa = secrets.randbelow( 0xffffffff )

for i in range(0,NUM_KEYS):
    from_time  = now + (KEY_LIFE * (i-1) )
    until_time = now + (KEY_LIFE * (i+1) )
    key = secrets.token_hex(KEY_LEN)
    sa_idx = start_sa + i
    # use AES
    transform_id = 3
    #random.randint( 2, 3 )

    sys.stdout.write("%d %d %d %d_%s\n"%(from_time, until_time, transform_id,sa_idx, key) )
