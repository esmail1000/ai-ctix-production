FROM node:22-bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y python3 python3-pip tesseract-ocr poppler-utils curl unzip && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm ci

COPY nlp_engine/requirements.txt ./nlp_engine/requirements.txt
RUN python3 -m pip install --break-system-packages -r ./nlp_engine/requirements.txt

COPY waf_simulation/requirements.txt.txt ./waf_simulation/requirements.txt.txt
RUN python3 -m pip install --break-system-packages -r ./waf_simulation/requirements.txt.txt

COPY . .

ARG CYBERBERT_MODEL_URL="https://github.com/esmail1000/ai-ctix-production/releases/download/model-v2/cyberbert-ner-verified.zip"

RUN rm -rf /app/nlp_engine/models/cyberbert-ner \
    && mkdir -p /app/nlp_engine/models/cyberbert-ner /tmp/cyberbert-model \
    && curl -L "$CYBERBERT_MODEL_URL" -o /tmp/cyberbert-ner-verified.zip \
    && unzip -o /tmp/cyberbert-ner-verified.zip -d /tmp/cyberbert-model \
    && cp -a /tmp/cyberbert-model/cyberbert-ner-verified/. /app/nlp_engine/models/cyberbert-ner/ \
    && rm -rf /tmp/cyberbert-model /tmp/cyberbert-ner-verified.zip \
    && test -f /app/nlp_engine/models/cyberbert-ner/config.json \
    && test -f /app/nlp_engine/models/cyberbert-ner/model.safetensors \
    && test -f /app/nlp_engine/models/cyberbert-ner/tokenizer.json \
    && test -f /app/nlp_engine/models/cyberbert-ner/tokenizer_config.json \
    && test -f /app/nlp_engine/models/cyberbert-ner/label_map.json

RUN npx prisma generate
RUN npm run build

EXPOSE 10000

CMD ["sh", "-c", "./node_modules/.bin/next start -H 127.0.0.1 -p 3000 & python3 -u waf_simulation/render_gateway.py"]
