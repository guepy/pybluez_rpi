FROM 172.16.3.80:5000/rfid_rpi_nodered_img:pythagore
ENV WDIR /usr/src/node-red/

WORKDIR WDIR
USER node-red
RUN npm fund
RUN npm install

CMD ["npm", "start"]
