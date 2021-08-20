from setuptools import setup, find_packages

setup(
    name="ckl_psm",
    version="1.0",
    author="snow0011",
    author_email="daslab@163.com",
    description="A password strength meter (PSM) with CKL_PCFG model",
    url="https://github.com/snow0011/CKL_PSM", 
    py_modules=["ckl_pcfg","fast_bpe_sim","monte_carlo_lib"],
    data_files=[("",
        ["resources/bpemodel.pickle",
        "resources/dangerous_chunks.pickle",
        "resources/monte_carlo_sample.pickle",
        "resources/intermediate_results.pickle"]
        )],
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)