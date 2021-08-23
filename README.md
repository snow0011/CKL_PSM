# Chunk-level Password Strength Meter and Password Recognization Tools
## 1. Chunk-level Password Strength Meter based on BPE_PCFG

### 1.1 Requirements  

- Python3.6 or Python3.8
- Node14.17 and yarn1.22 
- Ubuntu20.04 or Windows 10

### 1.2 Application startup  

#### 1.2.1 Back end  

```bash
cd backend
pip3 install -r requirements
python3 pcfg_server.py  # The default ip:port is <device local ip>:3001, and it MUSE BE <device local ip>:3001
```

#### 1.2.2 Front end  

```bash
cd frontend
yarn install
python3 ipconfig.py  # it is the same as: echo <device local ip> > ./src/ip.json
yarn build
yarn global add serve
~/.yarn/bin/serve build  # It will automatically choose a port
```

### 1.3 Preview  

![psm-crop-1](README.assets/CKL_PSM.png)

## 2. Chunk level PCFG Library

We also offer a chunk level PCFG library for password strength query. We hope this will help password manager create more secure tokens.   

### 2.1 How to build  

```bash
cd backend
# Install ckl_psm to current python environment
python setup.py install
```
or install by pip
```bash
pip install ckl-psm
```

### 2.2 How to use  

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

## 3. Memory pattern recognization

The folder "pattern_recognization" contains scripts that we use to recognize memory pattern in chunks and passwords. We focus on four type patterns in our paper: `leet pattern`, `syllable pattern`, `keyboard pattern` and `date pattern`. Input the password list and the scripts will output the passwords which meet the specific pattern. Here are details:  

```text
pattern_recognization/
├── leet.py         // Leet transformation rule detector. 
└── syllable.py         // Syllable pattern detector(include English syllable words and Chinese Pinyins).
├── kbd.py          // Detect keyboard patterns in chunks. 
├── date.py         // Date pattern recognization for chunks.
```


