SHELL := /bin/bash
# net features
net:
	sudo systemctl restart NetworkManager

# ssh
ssh:
	sudo systemctl restart sshd
	sudo systemctl restart ssh

# timezone & locales
locale:
	sudo chmod 0777 /etc/timezone /etc/locale.gen /etc/default/locale &&
	echo "Etc/GMT+5" > /etc/timezone &&
	sudo dpkg-reconfigure -f noninteractive tzdata &&
	sudo sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen &&
	sudo sed -i -e 's/# ru_RU.UTF-8 UTF-8/ru_RU.UTF-8 UTF-8/' /etc/locale.gen &&
	echo 'LANG="ru_RU.UTF-8"'>/etc/default/locale &&
	sudo dpkg-reconfigure --frontend=noninteractive locales && wait &&
	update-locale LANG=ru_RU.UTF-8 &&
	sudo chmod 0644 /etc/timezone /etc/locale.gen

# postgres
postgres:
	sudo systemctl stop postgrespro-1c-15
	sudo systemctl start postgrespro-1c-15

# ignore duplicate names
.PHONY: net ssh locale postgres
