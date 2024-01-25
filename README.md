# HomeAssistant Custom Components Ionos DNS Updater

Integration to update DNS entries on IONOS. Install it via HACS.

## Hacs Integration

Example `configuration.yaml` entry

```
sensor:
    - platform: ionos_dns_updater
      domain: ha.xyz.de
```

-   `domain`: The domain-name of your Home assistant installation
