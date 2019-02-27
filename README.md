# gitkanban tool
A tool to enhance Github issue management with Kanban flow

## Clone Git Repository
```
git clone https://github.com/deep-compute/gitkanban.git
cd gitkanaban
```

## Install gitkanban
```
pip install .
```

## Usage

Please verify whether the tool is installed properly or not

```
gitkanban --help
```
You would get something like this:

```
usage: gitkanban [-h] [--name NAME] [--log-level LOG_LEVEL]
                 [--log-format {json,pretty}] [--log-file LOG_FILE] [--quiet]
                 [--metric-grouping-interval METRIC_GROUPING_INTERVAL]
                 [--debug] [-auth GITHUB_ACCESS_TOKEN] [-u USERNAME]
                 [-p PASSWORD]
                 {ensure-labels,check-constraints,run} ...

optional arguments:
  -h, --help            show this help message and exit
  --name NAME           Name to identify this instance
  --log-level LOG_LEVEL
                        Logging level as picked from the logging module
  --log-format {json,pretty}
                        Force the format of the logs. By default, if the
                        command is from a terminal, print colorful logs.
                        Otherwise print json.
  --log-file LOG_FILE   Writes logs to log file if specified, default: None
  --quiet               if true, does not print logs to stderr, default: False
  --metric-grouping-interval METRIC_GROUPING_INTERVAL
                        To group metrics based on time interval ex:10 i.e;(10
                        sec)
  --debug               To run the code in debug mode
  -auth GITHUB_ACCESS_TOKEN, --github-access-token GITHUB_ACCESS_TOKEN
                        github account access token to authenticate
  -u USERNAME, --username USERNAME
                        github username
  -p PASSWORD, --password PASSWORD
                        github password

commands:
  {ensure-labels,check-constraints,run}
    ensure-labels       create or modify the labels
    check-constraints   check the label constraints
```

## 1. ensure-labels
It will create the labels and update the existing labels.
```
gitkanban ensure-labels -h

usage: gitkanban ensure-labels [-h] [--org ORG] [--repo REPO] --config-file
                               CONFIG_FILE

optional arguments:
  -h, --help            show this help message and exit
  --org ORG             github organization name
  --repo REPO           github repository name
  --config-file CONFIG_FILE
                        github label configuration file
```
run command
```
gitkanban -auth <github access token> ensure-labels  --org <organization-name> --repo <repository-name> --config-file <config file name>
```
