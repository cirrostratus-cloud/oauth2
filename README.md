# Cirrostratus - OAuth2

- [Cirrostratus - OAuth2](#cirrostratus---oauth2)
  - [Development](#development)
    - [Requirements](#requirements)
    - [Tests](#tests)

## Development

### Requirements

- Task: https://taskfile.dev/installation/
- Mockery: https://vektra.github.io/mockery/latest/installation/

### Tests

To create all needed mocks, you must configurate `.mockery.yaml` file and execute `mockery` command:

```shell
mockery
```

To run all test use the tests task commando:

```shell
task tests
```

