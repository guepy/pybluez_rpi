FROM python

WORKDIR $HOME/rfidproject
ENV WDIR $HOME/rfidproject
COPY $WDIR/nfs_rfidproject/ble_app/rpi_main_server_RFID.py $WDIR/rpi_main_server_RFID.py
COPY $WDIR/nfs_rfidproject/ble_app/entrypoint.sh $WDIR/entrypoint.sh
RUN sudo apt update
RUN sudo apt install -y d-feet
RUN pip install dbus-python
RUN pip install pybluez



CMD ./entrypoint.sh
