import httpclient
import std/[httpclient, json]

# Read input from user and assignt to URL variable
write(stdout, "Enter URL to request (i.e. http://x.x.x.x): ")
var url = readLine(stdin)

# If any input was received, try to request that with HTTP client, otherwise print error and exit
if len(url) != 0:
  # Build a basic GET request
  echo "[*] Making GET request to ", url
  var client = newHttpClient()
  echo "[+] Result: ", client.getContent(url)

  # Build a basic POST request with JSON
  echo "[*] Making POST request to ", url & "/register"
  client.headers = newHttpHeaders({ "Content-Type": "application/json" })
  let body = %*{
    "data": "secrets"
  }

  # Make the POST request
  let response = client.request(url & "/register", httpMethod = HttpPost, body = $body)
  echo "[+] Result: ", response.body

else:
    echo "Error reading URL."

