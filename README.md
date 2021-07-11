[![Build Status](https://github.com/gielfeldt/jwt-middleware/actions/workflows/test.yml/badge.svg)][4]
![Test Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/gielfeldt/38f85f4b39b31a62335059ff3708aded/raw/jwt-middleware__main.json)

[![Latest Stable Version](https://poser.pugx.org/gielfeldt/jwt-middleware/v/stable.svg)][1]
[![Latest Unstable Version](https://poser.pugx.org/gielfeldt/jwt-middleware/v/unstable.svg)][2]
[![License](https://poser.pugx.org/gielfeldt/jwt-middleware/license.svg)][3]
![Total Downloads](https://poser.pugx.org/gielfeldt/jwt-middleware/downloads.svg)


# Installation

```bash
composer require gielfeldt/jwt-middleware
```

# Usage

```php
<?php

use Gielfeldt\JwtMiddleware\HeaderTokenProvider;
use Gielfeldt\JwtMiddleware\JwtMiddleware;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Nyholm\Psr7\Factory\Psr17Factory;

require './vendor/autoload.php';

$config = Configuration::forUnsecuredSigner();
$clock = new SystemClock(new DateTimeZone('UTC'));
$constraint = new StrictValidAt($clock);
$config->setValidationConstraints($constraint);

$tokenProvider = new HeaderTokenProvider();
$responseFactory = new Psr17Factory();
$middleware = new JwtMiddleware($responseFactory, $config, $tokenProvider);


```

[1]:  https://packagist.org/packages/gielfeldt/jwt-middleware
[2]:  https://packagist.org/packages/gielfeldt/jwt-middleware#dev-main
[3]:  https://github.com/gielfeldt/jwt-middleware/blob/main/LICENSE.md
[4]:  https://github.com/gielfeldt/jwt-middleware/actions/workflows/test.yml
