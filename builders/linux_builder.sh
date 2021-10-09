cd ..
mkdir builds
mkdir builds/linux

echo "#!virtualenv/bin/python3" > builds/linux/scanz
cat source_code/main.py >> builds/linux/scanz
chmod +x builds/linux/scanz

if [ ! -d "builds/linux/virtualenv" ]
then
  virtualenv builds/linux/virtualenv
  builds/linux/virtualenv/bin/pip3 install -r source_code/requirments.txt
fi

zip linux_build builds/linux/*