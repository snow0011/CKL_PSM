# Chunk-level Password Strength Meter and Password Recognization Tools
## Chunk-level Password Strength Meter based on BPE_PCFG

### Requirements

- Python3.6 or Python3.8
- Node14.17 and yarn1.22 
- Ubuntu20.04 or Windows 10

### Application startup

#### Back end

```bash
cd backend
pip3 install -r requirements
python3 pcfg_server.py  # The default ip:port is <device local ip>:3001, and it MUSE BE <device local ip>:3001
```

#### Front end

```bash
cd frontend
yarn install
python3 ipconfig.py  # it is the same as: echo <device local ip> > ./src/ip.json
yarn build
yarn global add serve
~/.yarn/bin/serve build  # It will automatically choose a port
```

### Preview

![psm-crop-1](README.assets/psm-crop-1.svg)

## Memory pattern recognization

The folder "pattern_recognization" contains scripts that we use to recognize memory pattern in chunks and passwords. We focus on four type patterns in our paper: date pattern, keyboard pattern, leet pattern and syllable pattern. Input the password list and the scripts will output the passwords which meet the specific pattern. Here are details:  

```text
pattern_recognization/
├── date.py         // Date pattern recognization for chunks.
├── kbd.py          // Detect keyboard patterns in chunks. 
├── leet.py         // Leet transformation rule detector. 
└── syllable.py         // Syllable pattern detector(include English syllable words and Chinese Pinyins).
```


