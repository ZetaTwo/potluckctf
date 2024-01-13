#!/usr/bin/env bash
set -x

cd /app
mkdir frontend/static/secret
tar cvf frontend/static/secret/source-code.tar --exclude actual-flag /app /Dockerfile
gcc readflag.c -o readflag
npm install
npx tsc
cd /app/frontend
npm install
npm run build
cd /app

adduser app

chmod -R 755 /app

cp /app/flag.txt /app/flag
cp /app/flag.txt /flag
cp /app/flag.txt /flag.txt
chmod 755 /flag
chmod 755 /flag.txt

mkdir images
chown app images
touch images/pls-no-delete
chown root images/pls-no-delete

chmod 700 actual-flag
chmod u+s readflag
