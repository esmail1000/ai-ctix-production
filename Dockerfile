FROM node:22-bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y python3 python3-pip tesseract-ocr poppler-utils && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm ci

COPY nlp_engine/requirements.txt ./nlp_engine/requirements.txt
RUN python3 -m pip install --break-system-packages -r ./nlp_engine/requirements.txt

COPY waf_simulation/requirements.txt.txt ./waf_simulation/requirements.txt.txt
RUN python3 -m pip install --break-system-packages -r ./waf_simulation/requirements.txt.txt

COPY . .

RUN npx prisma generate
RUN npm run build

EXPOSE 10000

CMD ["sh", "-c", "./node_modules/.bin/next start -H 127.0.0.1 -p 3000 & python3 -u waf_simulation/render_gateway.py"]