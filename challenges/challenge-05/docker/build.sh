docker build --build-arg 'FLAG=potluck{Its_Raining_0days_13E7}' --tag savaoury_chall .
docker run -p 80:8631 -p 443:8632 --name savaoury -it savaoury_chall