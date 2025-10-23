# PHP Multi-Transform Encoder

A pure-stdlib Python tool to obfuscate PHP files with multiple reversible byte-level transforms
and generate a self-extracting PHP stub.

## Usage
```bash
python3 php_multi_transform_encoder_clean.py -i config.php -o output_config_1.php
python3 php_multi_transform_encoder_clean.py -i config.php -o output_config_1.php --no-eval
