FROM nginx:alpine

WORKDIR /usr/share/nginx/html

# Remove default nginx static resources
RUN rm -rf ./*

# Copy static files
COPY index.html .

# Expose port
EXPOSE 80

# Nginx runs as nginx by default
CMD ["nginx", "-g", "daemon off;"]