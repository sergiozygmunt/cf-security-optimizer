import CloudFlare
import requests
import sys
import os

# Define your Cloudflare email and API key here
CLOUDFLARE_EMAIL = ''
CLOUDFLARE_API_KEY = ''

def print_status(success, message):
    """Prints the status of an operation with a check mark or cross mark."""
    status_symbol = "[✓]" if success else "[✗]"
    print(f"{status_symbol} {message}\n")

def initialize_cloudflare(email, api_key):
    """Initialize the CloudFlare client using only email and API key."""
    print("[i] Initializing with API Key and Email")
    return CloudFlare.CloudFlare(email=email, key=api_key)

def get_zone_name():
    """Get the zone name from the command line argument."""
    if len(sys.argv) != 2:
        print("[✗] Incorrect usage. Please provide just the zone name.")
        sys.exit(1)
    return sys.argv[1]

def check_dns_record_exists(cf, zone_id, record_types, name):
    """Check if a DNS record of the specified types and name already exists."""
    for record_type in record_types:
        dns_records = cf.zones.dns_records.get(zone_id, params={'type': record_type, 'name': name})
        if dns_records:
            print_status(False, f"An existing {record_type} record found for {name}.")
            return True, record_type  # Record found, return True and the record type
    return False, None  # No record found, return False and None


def submit_domain_to_hsts_preload(domain_name):
    """Submit the domain to the HSTS preload list using a POST request."""
    url = f"https://hstspreload.org/api/v2/submit?domain={domain_name}"
    response = requests.post(url)
    if response.status_code == 200:
        response_json = response.json()
        if "errors" in response_json:
            for error in response_json["errors"]:
                print_status(False, f"Error: {error['summary']} - {error['message']}")
            if not response_json.get("errors"):
                print_status(True, f"Domain {domain_name} submitted to HSTS preload list successfully.")
        if "warnings" in response_json:
            for warning in response_json["warnings"]:
                print(f"Warning: {warning['summary']} - {warning['message']}")
    else:
        print_status(False, f"Failed to submit domain {domain_name} to HSTS preload list. Status code: {response.status_code}")
        print("Response text:", response.text)

def main():
    os.environ.pop('CF_API_KEY', None)
    os.environ.pop('CF_API_EMAIL', None)
    os.environ.pop('CF_API_TOKEN', None)
    
    zone_name = get_zone_name()
    cf = initialize_cloudflare(email=CLOUDFLARE_EMAIL, api_key=CLOUDFLARE_API_KEY)

    print(f"\n------[ Domain level checks for ]-----\nName:    {zone_name}\n")

    try:
        zones = cf.zones.get(params={'name': zone_name})
        if not zones:
            print_status(False, 'No zones found for the specified name.')
            return
        zone_id = zones[0]['id']
        print_status(True, f"Zone ID: {zone_id}")
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        print_status(False, f'Error fetching zone information: {e}')
        return

    # Enable DNSSEC
    try:
        cf.zones.dnssec.patch(zone_id, data={'status': 'active'})
        print_status(True, "DNSSEC enabled successfully.")
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        print_status(False, f"Failed to enable DNSSEC: {e}")

    # DNS Records Check and Management
    try:
        record_exists, record_type = check_dns_record_exists(cf, zone_id, ['AAAA', 'A', 'CNAME'], '@')
        if not record_exists:
            cf.zones.dns_records.post(zone_id, data={
                'name': '@',
                'type': 'AAAA',
                'content': '100::',
                'ttl': 120,
                'proxied': True
            })
            print_status(True, "AAAA record for @ with value 100:: created successfully.")
        else:
            print_status(False, f"An existing {record_type} record prevents AAAA record creation for '@'.")
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        print_status(False, f"Failed to manage DNS records: {e}")

    # Zone Settings Updates
    try:
        settings = {
            'ssl': {'value': 'strict'},
            'min_tls_version': {'value': '1.2'},
            'tls_1_3': {'value': 'on'},
            'always_use_https': {'value': 'on'},
            'automatic_https_rewrites': {'value': 'on'},
            'security_header': {
                'strict_transport_security': {
                    'enabled': True,
                    'max_age': 31536000,
                    'include_subdomains': True,
                    'preload': True,
                    'nosniff': True
                }
            }
        }
        for setting, data in settings.items():
            cf.zones.settings.patch(zone_id, setting, data=data)
            print_status(True, f"{setting} updated successfully.")
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        print_status(False, f"Failed to update zone settings: {e}")

    # SPF Record Handling
    try:
        dns_records = cf.zones.dns_records.get(zone_id, params={'type': 'TXT'})
        spf_exists = any('v=spf1' in record['content'] for record in dns_records)
        if not spf_exists:
            cf.zones.dns_records.post(zone_id, data={'name': '@', 'type': 'TXT', 'content': 'v=spf1 -all', 'ttl': 120})
            print_status(True, "SPF record for no email added successfully.")
        else:
            print_status(False, "Existing SPF record found. No new SPF record added.")
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        print_status(False, f"Failed to manage SPF records: {e}")

    # HSTS Preload List Submission
    submit_domain_to_hsts_preload(zone_name)

    print("Configuration complete.\n")

if __name__ == '__main__':
    main()
