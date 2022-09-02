 #!/bin/sh
 set -x
 echo "start"
 echo "Updating packages database..."
 sudo apt update 
 sudo apt upgrade -y
 echo "[OK]"
 echo "Downloading required packages..."
 sudo apt install  -y python3 
 sudo apt install  -y python3-dev
 sudo apt install  -y python3-pip 
 sudo apt install  -y python3-gi python3-gi-cairo gir1.2-gtk-3.0	
 sudo apt install  -y d-feet
 sudo apt install git dbus
 pip install dbus-python
 pip install pybluez
 
 echo "[OK]"
 if [ -f "./get-docker.sh" ]
 then 
	echo "Installing docker tools..."
	sudo sh ./get-docker.sh
 else
	echo "Make sure docker is install on your host"
 fi
 echo "[OK]"
 sudo usermod -aG docker ${USER}
echo "Clonning docker compose..."
 git clone https://github.com/docker/compose.git
 echo "[OK]"
 echo "Installing docker compose..."
 cd ./compose
 make
 echo "[OK]"
 cd ..
 #This is for use of personnal docker registry
 #sudo sh -c "echo { \"insecure-registries\":[\"172.16.3.80:5000\"] } >> /etc/docker/daemon.json"
 echo "export DOCKER_BUILDKIT=1" >> ~/.bashrc
 echo "export COMPOSE_DOCKER_CLI_BUILD=0" >> ~/.bashrc
 source ~/.bashrc
 #adresse du broker kafka
 sudo sh -c "echo \"195.221.0.168 sun-si-pluss\" >> /etc/hosts"
 cd ~/rfidproject
 if [ -d "./pyBluez" ]
 then
	rm -Rfa ./pyBluez
 fi
 sudo chown -R ${USER}:${USER} .
 docker compose build
 docker compose up -d
 echo "[Finished]"
