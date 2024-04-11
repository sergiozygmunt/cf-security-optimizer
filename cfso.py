import CloudFlare
import requests
import sys

def print_status(success, message):
    """Prints the status of an operation with a check mark or cross mark."""
    status_symbol = "[✓]" if success else "[✗]"
    print(f"{status_symbol} {message}\n")

def initialize_cloudflare(api_token=None, email=None, api_key=None):
    """Initialize the CloudFlare client based on available credentials."""
    if api_token:
        print("[i] Initializing with API Token")
        return CloudFlare.CloudFlare(token=api_token)
    elif email and api_key:
        print("[i] Initializing with API Key and Email")
        return CloudFlare.CloudFlare(email=email, token=api_key)
    else:
        print("[✗] No valid credentials provided.")
        sys.exit(1)

def determine_arguments():
    """Determine the mode of operation based on the command line arguments."""
    if len(sys.argv) == 4:
        return sys.argv[1], sys.argv[2], sys.argv[3]
    elif len(sys.argv) == 3:
        return sys.argv[1], sys.argv[2], None
    else:
        print("[✗] Incorrect usage. Please provide the zone name and either an API token or email and API key.")
        sys.exit(1)

def check_dns_record_exists(cf, zone_id, record_types, name):
    """Check if a DNS record of the specified types and name already exists."""
    for record_type in record_types:
        dns_records = cf.zones.dns_records.get(zone_id, params={'type': record_type, 'name': name})
        if dns_records:
            print_status(False, f"An existing {record_type} record found for {name}.")
            return True, record_type
    return False, None

def submit_domain_to_hsts_preload(domain_name):
    """Submit the domain to the HSTS preload list using a POST request."""
    url = "https://hstspreload.org/api/v2/submit"
    data = {'domain': domain_name}
    response = requests.post(url, data=data)
    if response.status_code == 200:
        response_json = response.json()
        if "errors" in response_json:
            for error in response_json["errors"]:
                print_status(False, f"{error['summary']} - {error['message']}")
        else:
            print_status(True, "Domain submitted to HSTS preload list successfully.")
        if "warnings" in response_json:
            for warning in response_json["warnings"]:
                print(f"[i] {warning['summary']} - {warning['message']}")
    else:
        print_status(False, f"Failed to submit domain to HSTS preload list. Status code: {response.status_code}")

def main():
    zone_name, api_token, api_key = determine_arguments()
    cf = initialize_cloudflare(api_token=api_token, email=zone_name, api_key=api_key)

    print(f"\n------[ Domain level checks for ]-----\nName:    {zone_name}\n")

    zones = cf.zones.get(params={'name': zone_name})
    if not zones:
        print_status(False, 'No zones found for the specified name.')
        return
    zone_id = zones[0]['id']
    print_status(True, f"Zone ID: {zone_id}")

    # Enable DNSSEC
    try:
        cf.zones.dnssec.patch(zone_id, data={'status': 'active'})
        print_status(True, "DNSSEC enabled successfully.")
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        print_status(False, f"Failed to enable DNSSEC: {e}")

    # Check for existing DNS records
    record_exists, record_type = check_dns_record_exists(cf, zone_id, ['AAAA', 'A', 'CNAME'], '@')
    if not record_exists:
        try:
            cf.zones.dns_records.post(zone_id, data={
                'name': '@',
                'type': 'AAAA',
                'content': '100::',
                'ttl': 120,
                'proxied': True
            })
            print_status(True, "AAAA record for @ with value 100:: created successfully.")
        except CloudFlare.exceptions.CloudFlareAPIError as e:
            print_status(False, f"Failed to create AAAA record: {e}")
    elif record_type == 'CNAME':
        print_status(False, "A CNAME record for the root domain already exists. Cannot create AAAA record.")

    # Zone settings updates
    settings = {
        'ssl': {'value': 'strict'},
        'min_tls_version': {'value': '1.2'},
        'tls_1_3': {'value': 'on'},
        'always_use_https': {'value': 'on'},
        'automatic_https_rewrites': {'value': 'on'},
        'security_header': {
            'value': {
                'strict_transport_security': {
                    'enabled': True,
                    'max_age': 31536000,  # Maximum age in seconds
                    'include_subdomains': True,
                    'preload': True,
                    'nosniff': True
                }
            }
        }
    }
    for setting, data in settings.items():
        try:
            cf.zones.settings.patch(zone_id, setting, data=data)
            print_status(True, f"{setting} updated successfully.")
        except CloudFlare.exceptions.CloudFlareAPIError as e:
            print_status(False, f"Failed to update {setting}: {e}")

    # SPF record only if no existing SPF record is found
    dns_records = cf.zones.dns_records.get(zone_id, params={'type': 'TXT'})
    if not any('v=spf1' in record['content'] for record in dns_records):
        try:
            cf.zones.dns_records.post(zone_id, data={'name': '@', 'type': 'TXT', 'content': 'v=spf1 -all', 'ttl': 120})
            print_status(True, "SPF record for no email added successfully.")
        except CloudFlare.exceptions.CloudFlareAPIError as e:
            print_status(False, f"Failed to add SPF record: {e}")

    # Submit domain to HSTS preload list
    submit_domain_to_hsts_preload(zone_name)

    print("Configuration complete.\n")

if __name__ == '__main__':
    main()
