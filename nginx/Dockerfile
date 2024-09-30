FROM nginx:alpine

# Install openssl
RUN apk add --no-cache openssl

# Generate SSL certificates
RUN mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/nginx.key \
    -out /etc/nginx/ssl/nginx.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=Department/CN=localhost"

# Copy nginx configuration file
COPY nginx.conf /etc/nginx/nginx.conf

# Start nginx server
CMD ["nginx", "-g", "daemon off;"]