FROM node:20.9.0

WORKDIR /user-acc-mgmt-serv

COPY package.json .

RUN yarn install

COPY . .

CMD yarn prisma:generate && PRISMA_SCHEMA_DISABLE_ADVISORY_LOCK=true yarn prisma:migrate:dev && sleep 30 && yarn start