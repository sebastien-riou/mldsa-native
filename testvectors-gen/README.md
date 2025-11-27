# test vectors generation to benchmark ML-DSA sign operation

## How to generate the test vectors

1. use `buildit` script to build the native program, i.e. `./buildit`
2. use `search` script to find a high repetition count case, i.e. `./search 44 50 2M 00 2`
3. use `log_aborts_long_msg_sizes` script to find single repetition cases for the same hdrbg seed, i.e. `./log_aborts_long_msg_sizes 44 00`
4. use `mldsa-sign-tvgen.py` script to generate the test vectors, i.e. `pipenv run python mldsa-sign-tvgen.py --read-log results/`

## How to use the test vectors

### Python

````
import runpy
import gen_mldsa_inputs

# Get the parameters
params = runpy.run_path('results/mldsa44-m69-h30D1C064.sel.py')

# Generate the inputs
messages, mprimes, mus = gen_mldas_inputs(params)
sigs = bytearray()

# Process the inputs, here for pure ML-DSA.Sign
for message in messages:
    # TODO: compute the signature here
    sigs += sig

# verify digest over signatures
digest = hashlib.sha256(sigs).digest()
if digest == params['sigs_sha256_digest']:
    print('all test vectors executed correctly')
else:
    raise RuntimeError()

````

### C

````
#include <stdint.h>
#include "results/mldsa44-m69-h30D1C064.c"

void gen_message(unsigned int index, uint8_t*dst, size_t dst_size){

}
````

### System verilog

````
````
