FROM rpinodered:pythagore
ENV WDIR /usr/src/node-red/

WORKDIR WDIR
COPY ./volumes/rpinodered/_data/ /data/

USER node-red
RUN npm fund
RUN npm install

CMD ["npm", "start"]
