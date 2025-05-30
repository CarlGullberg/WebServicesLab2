#!/bin/bash


echo "Hämtar access token..."
token_response=$(curl -s -u client-id:secret \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=quotes.read" \
  http://localhost:9000/oauth2/token)

access_token=$(echo "$token_response" | grep -o '"access_token":"[^"]"' | cut -d':' -f2 | tr -d '"')

if [ -z "$access_token" ]; then
  echo "Kunde inte hämta token:"
  echo "$token_response"
  exit 1
fi

echo "Token hämtad!"


echo "Anropar /quotes/random via gateway (localhost:8081)..."
response=$(curl -s -w "\nHTTP_STATUS:%{http_code}" \
  -H "Authorization: Bearer $access_token" \
  http://localhost:8081/quotes/random)




body=$(echo "$response" | sed -e 's/HTTP_STATUS:.//g')
status=$(echo "$response" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')

echo "Svarskod: $status"
echo "Svar:"
echo "$body"