# HTTP conformance project
This repository contains the code for our paper: "Who's Breaking the Rules? Studying Conformance to the HTTP Specifications and its Security Impact" [ACM ASIACCS 2024](TODO).
It contains a test suite for HTTP conformance tests of responses and test runners to run it on both local web servers and on real websites.

## Structure
- [conformance_checker.py](conformance_checker.py): MitM-Proxy script to record all traffic and run all probe tests
- [run_checks.py](run_checks.py): Main test runner: run tests either on local web server installations or real websites
- [testcases.py](testcases.py): All 106 rules mined from the specifications with tests implementing them
- [pyproject.toml](pyproject.toml): Poetry File for reproducible installation
- [tested_orgins.csv](tested_origins.csv): List of all origins tested in the paper
- `testbed/`: Local server testbed (optional)
    - [docker-compose.yml](testbed/docker-compose.yml): Configuration file for locally hosting the 9 tested servers.
    - [versions.tex](testbed/versions.tex): Table listing the tested versions (same as in the configuration file)
- `sanity_check/`: Sanity checking of implemted testcases (optional)
    - [serve_testcases.py](sanity_check/serve_testcases.py): Serves example responses to test whether the testcases measure what they are supposed to measure
    - [check_testcases.py](sanity_check/check_testcases.py): Visits all example responses to collect data for sanity checking the testcases
    - [sanity.ipynb](sanity_check/sanity.ipynb): Jupyter Notebook for analyzing the sanity check results
- `helpers/`: Various helper functions and analysis scripts
    - [analysis_paper.ipynb](helpers/analysis_paper.ipynb): Main Jupyter Notebook for analyzing the results presented in the paper
    - [analysis_stats.ipynb](helpers/analysis_stats.ipynb): Jupyter Notebook for high level analysis of the testcases and used specifications
    - [db_util.py](helpers/db_util.py): Utility functions for working with the database
    - [direct_util.py](helpers/direct_util.py): Utility functions for the direct tests
    - [redbot_requestor.py](helpers/redbot_requestor.py): Wrapper around REDBot
    - [requestors.py](helpers/requestors.py): Wrapper around HTTPX
    - [syntax_validation.py](helpers/syntax_validation.py): Utility functions for ABNF tests
    - `syntax/*`: ABNF definitions
    - [util.py](helpers/util.py): General utility functions

## Installation
- Clone the repo (with submodules): `git clone --recurse-submodules`
- Installation:
    - Install poetry: https://python-poetry.org/docs/
    - Run: `poetry install`
    - Run `poetry run pip install ./redbot` to install a local version of redbot!
    - Patch the dpkt library: `sh fix_dpkt.sh`
    - (Optional) Install docker, necessary for local tests: https://docs.docker.com/get-docker/
    - Run `mv .env.example .env` and change the content to point to a reachable PostgreSQL instance. The user needs the rights to create new databases.

## Usage
- Run on local servers:
    - Start the local severs: `cd testbed && docker compose up -d`
    - Enable HTTP2 for jetty: `docker exec testbed-jetty-1 bash -c "java -jar  /usr/local/jetty/start.jar --add-modules=ssl,http2,https,test-keystore"`, then restart jetty `docker compose restart jetty`
    - Start testing the local servers: `cd .. && poetry run python run_checks.py --mode=local`
- Run on popular websites:
    - Recommended if running on real websites: Add a mattermost hook and a link to your crawl in [util.py](helpers/util.py)
    - Start testing popular websites: `poetry run python run_checks.py --mode=popular --max_workers=20`
- Optional sanity checking:
    - Add `127.0.0.1 leaking.via` to `/etc/hosts`
    - Start serving the sample responses: `cd sanity_check && poetry run python serve_testcases.py`
    - Test the sample responses (new terminal): `cd sanity_check && poetry run python check_testcases.py`
    - Analyze the results: run `poetry run jupyter lab` open `sanity.ipynb`
- Analyze the results:
    - Start jupyterlab: `poetry run jupyter lab`
    - General statistics of the tests and rules: `helpers/analysis_stats.ipynb`
    - Result analysis (local or popular): `helpers/analysis_paper.ipynb`


## Contact

If there are questions about our tools or paper, please either file an issue or contact `jannis.rautenstrauch (AT) cispa.de`.

## Research Paper

The paper is available at the [ACM Digital Library](TODO). 
You can cite our work with the following BibTeX entry:
```latex
@inproceedings{RautenstrauchWho2024,
 author = {Rautenstrauch, Jannis and Stock, Ben},
 booktitle = {ACM ASIACCS},
 title = {{Who's Breaking the Rules? Studying Conformance to the HTTP Specifications and its Security Impact}},
 year = {2024},
 doi = {TODO},
}
