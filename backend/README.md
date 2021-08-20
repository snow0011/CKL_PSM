# Chunk level PCFG Library

We offer a chunk level PCFG library for password strength query. We hope this will help password manager create more secure tokens.   

### How to build  

```bash
cd backend
# Install ckl_psm to current python environment
python setup.py install
```
or install by pip

```bash
pip install ckl-psm
```

### How to use  

```python
# Import ckl_psm and make sure you have installed the library
import ckl_pcfg as psm

# Strength query for given password
result = psm.check_pwd("123456")

# The result is consist of four parts:
print(
    result["guess_number"],
    result["segments"],
    result["chunks"],
    result["prob"]
)

```