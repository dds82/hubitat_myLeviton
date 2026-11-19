FROM node:22-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY proxy.js ./

RUN mkdir -p /logs
VOLUME ["/logs"]

EXPOSE 8088

CMD ["node", "proxy.js"]