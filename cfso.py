import CloudFlare
import requests
import sys  # Import sys module to access command line arguments

def print_status(success, message):
    """Prints the status of an operation with a check mark or cross mark."""
    status_symbol = "[✓]" if success else "[✗]"
    print(f"{status_symbol} {message}\n")

def check_dns_record_exists(cf, zone_id, record_types, name):
    """Check if a DNS record of the specified types and name already exists."""
    for record_type in record_types:
        try:
            dns_records = cf.zones.dns_records.get(zone_id, params={'type': record_type, 'name': name})
            if dns_records:
                print_status(False, f"An existing {record_type} record found for {name}.")
                return True
        except CloudFlare.exceptions.CloudFlareAPIError as e:
            print_status(False, f"Error checking for existing {record_type} records: {e}")
    return False

def submit_domain_to_hsts_preload(domain_name):
    """Submit the domain to the HSTS preload list using a POST request with the domain as a URL parameter."""
    url = f"https://hstspreload.org/api/v2/submit?domain={domain_name}"
    try:
        response = requests.post(url)
        if response.status_code == 200:
            response_json = response.json()
            if response_json.get("errors"):
                for error in response_json["errors"]:
                    print_status(False, f"{error['summary']} - {error['message']}")
                return  # Return early as the submission failed due to errors
            else:
                print_status(True, f"Domain {domain_name} submitted to HSTS preload list successfully.")

            if response_json.get("warnings"):
                for warning in response_json["warnings"]:
                    print(f"[i] {warning['summary']} - {warning['message']}\n")
        else:
            print_status(False, f"Failed to submit domain {domain_name} to HSTS preload list. Status code: {response.status_code}, Response: {response.text}")
    except requests.exceptions.RequestException as e:
        print_status(False, f"Error submitting domain to HSTS preload list: {e}")

def main():
    token = "CHANGE ME"  # Placeholder token
    
    # Check if a domain name was passed as a command line argument
    if len(sys.argv) > 1:
        zone_name = sys.argv[1]
    else:
        # If no domain name was provided, ask for it
        zone_name = input("Enter your Zone Name (domain name): \n")

    cf = CloudFlare.CloudFlare(token=token)

    print(f"\n------[ Domain level checks for ]-----\nName:    {zone_name}\n")

    # Get the Zone ID
    try:
        zones = cf.zones.get(params={'name':zone_name})
        if not zones:
            print_status(False, 'No zones found for the specified name.')
            return
        else:
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

    # Check if an AAAA or A record already exists for "@"
    if not check_dns_record_exists(cf, zone_id, ['AAAA', 'A'], '@'):
        # Create an AAAA record for @ with value 100:: and proxy status on
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

    # Update zone settings
    settings_to_update = {
        'ssl': {'value': 'strict'},
        'min_tls_version': {'value': '1.2'},
        'tls_1_3': {'value': 'on'},
        'always_use_https': {'value': 'on'},
        'automatic_https_rewrites': {'value': 'on'},
        'security_header': {
            'value': {
                'strict_transport_security': {
                    'enabled': True,
                    'max_age': 31536000,  # 12 months in seconds
                    'include_subdomains': True,
                    'preload': True,
                    'nosniff': True
                }
            }
        }
    }

    for setting, value in settings_to_update.items():
        try:
            cf.zones.settings.patch(zone_id, setting, data=value)
            print_status(True, f"{setting} set successfully.")
        except CloudFlare.exceptions.CloudFlareAPIError as e:
            print_status(False, f"Failed to set {setting}: {e}")

    # Check and add SPF record ONLY IF NO existing SPF record is found
    try:
        dns_records = cf.zones.dns_records.get(zone_id, params={'type':'TXT'})
        if not any('v=spf1' in record['content'] for record in dns_records):
            cf.zones.dns_records.post(zone_id, data={'name': '@', 'type': 'TXT', 'content': 'v=spf1 -all', 'ttl': 120})
            print_status(True, "SPF record for no email added successfully.")
        else:
            print_status(False, "Existing SPF record found. No new SPF record added.")
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        print_status(False, f"Failed to check or add SPF record: {e}")

    # Submit domain to HSTS preload list
    submit_domain_to_hsts_preload(zone_name)

    print("Configuration complete.\n")

if __name__ == '__main__':
    main()
