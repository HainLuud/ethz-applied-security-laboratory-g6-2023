# Use a base image with Nginx preinstalled
FROM nginx:alpine

# Copy your Nginx configuration into the container
COPY nginx.conf /etc/nginx/nginx.conf

# Copy your SSL certificates into the container
COPY server.crt /etc/nginx/server.crt
COPY server.key /etc/nginx/server.key
COPY ca.crt     /etc/nginx/ca.crt

# Expose the SSL port
EXPOSE 443

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]
