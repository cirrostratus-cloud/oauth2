# Cirrostratus - OAuth2

- [Cirrostratus - OAuth2](#cirrostratus---oauth2)
  - [Development](#development)
    - [Branching](#branching)
    - [Tagging](#tagging)
    - [Requirements](#requirements)
    - [Tests](#tests)

## Development

### Branching

- [Semantic Commit Messages](https://gist.github.com/joshbuchea/6f47e86d2510bce28f8e7f42ae84c716)

### Tagging

- [Semantic Versioning](https://semver.org/)

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

