# HomeAssistant Custom Components Ionos DNS Updater

Integration to update DNS entries on IONOS. Install it via HACS.

## Hacs Integration

Example `configuration.yaml` entry

```cmd
sensor:
    - platform: ionos_dns_updater
      domain: ha.xyz.de
      zone_domain: xyz.de
      prefix: XXXXXX
      encryption: YYYYY
      log_http_errors: False
      dns_api_timeout: 10
      time_to_live: 300
```

- `domain`: The domain-name of your Home assistant installation
- `zone_domain`: (Optional, defaults to ""), if you want to update the dns settings in the IONONS API, the correct record-zone needs to be selected from the dns settings
- `prefix`: (Optional, defaults to ""), if you want to update the dns settings in the IONONS API, this defines the access prefix
- `encryption`: (Optional, defaults to ""), if you want to update the dns settings in the IONONS API, this defines the access key
- `log_http_errors`: (Optional, defaults to False), whether to log ALL http errors (many are recoverable and could spam logs if everything is working)
- `dns_api_timeout`: (Optional, defaults to 10), correct to control the timeout of the DNS API
- `time_to_live`: (Optional, defaults to 300), the ttl to be set for the dns entry

## How to generate an API token

Go to [API keys manager](https://developer.hosting.ionos.de/keys).

This is derived from [this API](https://developer.hosting.ionos.de/docs).
