FROM node:22-bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y python3 python3-pip tesseract-ocr poppler-utils && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm ci

COPY nlp_engine/requirements.txt ./nlp_engine/requirements.txt
RUN python3 -m pip install --break-system-packages -r ./nlp_engine/requirements.txt

COPY . .

RUN npx prisma generate
RUN npm run build

EXPOSE 3000

CMD ["npm", "run", "start"]
