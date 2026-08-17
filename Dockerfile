FROM apify/actor-node:22

COPY package*.json ./
RUN npm --quiet set progress=false && npm ci --omit=dev --omit=optional

COPY . ./
CMD ["npm", "start"]
