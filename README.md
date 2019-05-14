# gitkanban tool
A tool to enhance Github issue management with Kanban flow

## Install gitkanban
```
pip install gitkanban
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
                 [--debug] [-a GITHUB_ACCESS_TOKEN] [-u USERNAME]
                 [-p PASSWORD] --config-file CONFIG_FILE
                 {ensure-labels,check-constraints,ensure-repo-group-labels,snooze,sync,run}
                 ...

A tool to enhance Github issue management with Kanban flow

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
  -a GITHUB_ACCESS_TOKEN, --github-access-token GITHUB_ACCESS_TOKEN
                        github account access token to authenticate
  -u USERNAME, --username USERNAME
                        github username
  -p PASSWORD, --password PASSWORD
                        github password
  --config-file CONFIG_FILE
                        check the config file ex: conf.json or config.conf

commands:
  {ensure-labels,check-constraints,ensure-repo-group-labels,snooze,sync,run}
    ensure-labels       create or modify the labels
    check-constraints   check the label constraints
    ensure-repo-group-labels
                        create the repo_group labels to the repo in that group
    snooze              remind the issues after time duration
    sync                Sync full state from Github
```

## 1. ensure-labels
It will create the labels and update the existing labels.
```
gitkanban --log-file <filename.log> -a <github access token> --config-file <config file name> ensure-labels
```

## 2. check-constraints
It will execute the constraints on Github issues and raise alerts for the issues.
```
gitkanban --log-file <filename.log> -a <github access token> --config-file <config file name> check-constraints -a <aler_repo> --db <dbname.db>
```

## 3. ensure-repo-group-labels
It will add the team label to the repo-group team repository issues.
```
gitkanban --log-file <filename.log> -a <github access token> --config-file <config file name> ensure-repo-group-labels
```

## 4. snooze (reminder)
Move issues to in-progress from other queues when snooze time expires.
```
gitkanban --log-file <filename.log> -a <github access token> --config-file <config file name> snooze
```
