FROM node:20.9.0

WORKDIR /user-acc-mgmt-serv

COPY package.json .

RUN yarn install

COPY . .

CMD yarn start