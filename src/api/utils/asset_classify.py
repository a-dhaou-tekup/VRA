"""Infer asset_type and platform from hostname + os_version.

Used in bulk-import path and the backfill endpoint so existing assets without
these fields can be classified automatically.
"""

from __future__ import annotations

_HOSTNAME_TYPE: list[tuple[list[str], str]] = [
    (['laptop-', 'lt-', 'nb-'],                               'laptop'),
    (['ws-', 'workstation-', 'wks-', 'desktop-'],             'workstation'),
    (['fw-', 'firewall-', 'palo-', 'forti-', 'ngfw-'],        'network_device'),
    (['sw-', 'switch-', 'rtr-', 'router-', 'core-'],          'network_device'),
    (['k8s-', 'kube-', 'docker-', 'container-'],              'container'),
    (['vm-', 'virt-'],                                         'virtual_machine'),
    (['cloud-', 'ec2-', 'gcp-', 'azure-', 'cdn-'],            'cloud_instance'),
    (['mobile-', 'iphone-', 'android-'],                      'mobile'),
    (['web-', 'db-', 'app-', 'api-', 'srv-', 'server-',
      'mon-', 'log-', 'backup-', 'nas-', 'mail-', 'proxy-',
      'vpn-', 'siem-', 'jump-', 'ci-', 'build-', 'runner-',
      'k8s-master', 'k8s-node'],                              'server'),
]

_OS_PLATFORM: list[tuple[list[str], str, str]] = [
    # (keywords_in_os, platform, fallback_asset_type)
    (['windows 11', 'windows 10', 'windows 8', 'windows 7'],  'Windows',            'workstation'),
    (['windows server'],                                        'Windows Server',     'server'),
    (['macos', 'mac os'],                                       'macOS',              'laptop'),
    (['ubuntu', 'debian', 'rhel', 'red hat enterprise',
      'centos', 'almalinux', 'fedora', 'rocky'],               'Linux',              'server'),
    (['freebsd'],                                               'FreeBSD',            'server'),
    (['esxi', 'vmware esxi'],                                   'VMware ESXi',        'server'),
    (['pan-os', 'palo alto pan-os'],                            'Palo Alto PAN-OS',   'network_device'),
    (['fortios', 'fortinet fortios'],                           'Fortinet FortiOS',   'network_device'),
    (['ios xe', 'ios xr', 'nx-os'],                             'Cisco IOS',          'network_device'),
    (['junos'],                                                 'Juniper JunOS',      'network_device'),
    (['chromeos'],                                              'ChromeOS',           'workstation'),
    (['ios 1', 'ios 2'],                                        'iOS',                'mobile'),
    (['android'],                                               'Android',            'mobile'),
    (['embedded linux'],                                        'Embedded Linux',     'iot_device'),
    (['freertos', 'vxworks', 'zephyr'],                         'RTOS',               'iot_device'),
    (['amazon linux'],                                          'Linux',              'cloud_instance'),
]


def infer(hostname: str, os_version: str) -> tuple[str | None, str | None]:
    """Return (asset_type, platform) inferred from hostname and os_version.

    Returns (None, None) when no rule matches.
    """
    h = (hostname or '').lower()
    o = (os_version or '').lower()

    # Step 1: platform from os_version (drives fallback asset_type too)
    platform: str | None = None
    os_asset_type: str | None = None
    for keywords, plat, fallback in _OS_PLATFORM:
        if any(kw in o for kw in keywords):
            platform = plat
            os_asset_type = fallback
            break

    # Step 2: asset_type from hostname prefix (higher priority than OS fallback)
    asset_type: str | None = None
    for prefixes, atype in _HOSTNAME_TYPE:
        if any(h.startswith(p) or p in h for p in prefixes):
            asset_type = atype
            break

    # Fall back to OS-derived type if hostname gave nothing
    if asset_type is None:
        asset_type = os_asset_type

    return asset_type, platform
