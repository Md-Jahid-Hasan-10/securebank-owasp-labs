FROM node:18-alpine AS build
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
# Stamped into the bundle and shown in the top bar, so a browser tab that is
# still running an older build is immediately visible.
ARG APP_BUILD=unknown
ENV APP_BUILD=${APP_BUILD}
RUN npm run build

FROM nginx:1.25-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
