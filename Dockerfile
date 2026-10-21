FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev && npm cache clean --force
COPY server ./server
USER node
EXPOSE 8080
CMD ["node", "server/index.js"]
