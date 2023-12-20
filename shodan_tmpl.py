import shodan
import requests

# Set up Shodan API client with your API key
api = shodan.Shodan('APIKEY')

# Define your query to search for
query = 'title:251'

# Perform the search and extract the IP addresses
try:
    # Search Shodan with your query
    results = api.search(query)

    # Extract the IP addresses from the results
    ip_list = [result['ip_str'] + ':' + str(result['port']) for result in results['matches']]

    # Write the IP addresses to a file
    with open('ip_list.txt', 'w') as f:
        f.write('\n'.join(ip_list))

except shodan.APIError as e:
    print('Error: %s' % e)

# Loop through the IP addresses and make GET requests to the discovered hosts
with open('results.txt', 'w') as f:
    for ip in ip_list:
        url = 'http://' + ip + '/status.xml'
        try:
            response = requests.get(url)
            if response.text:
                print('Getting data from: ', ip)
                f.write(ip)
                f.write(response.text)
                f.write('\n')
        except:
            pass
