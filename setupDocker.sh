 #!/bin/sh
 set -x
 echo "start"
 echo "creating folder rfid project..."
 mkdir -p ~/rfidproject
 echo "[OK]"
 echo "cd to folder rfid project..."
 cd ~/rfidproject
 echo "[OK]"
 
 echo "Updating packages database..."
 #sudo apt update 
 #sudo apt upgrade -y
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
 echo "Downloading docker setup file..."
 if [ -f "./get-docker.sh" ]
 then 
	echo "file already exist"
 else
	curl -fsSL https://get.docker.com -o get-docker.sh
	chmod +x ./get-docker.sh
	echo "Installing docker tools..."
	sudo sh ./get-docker.sh
 fi
 echo "[OK]"
 sudo usermod -aG docker ${USER}
 echo "[OK]"
 echo "Clonnig docker compose directory..."
 if [ -d "./compose" ]
 then
	echo "Directory compose already exist"
 else 
	git clone https://github.com/docker/compose.git
 echo "Installing docker compose..."
 cd ./compose
 make
 fi
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
 #git clone https://github.com/guepy/pybluez_rpi.git pyBluez
 git clone https://gitlab.synchrotron-soleil.fr/eca/tests_gitlab/sensors/rfidproject.git pyBluez
 cd pyBluez
 git pull https://gitlab.synchrotron-soleil.fr/eca/tests_gitlab/sensors/rfidproject.git develop

 sudo chown -R ${USER}:${USER} .
 #git checkout -b develop
 docker compose build
 docker compose up -d
 echo "[Finished]"
