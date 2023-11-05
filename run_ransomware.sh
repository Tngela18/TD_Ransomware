mkdir -p token_data
docker run -it --rm --name ransomware \
    --net=ransomware-network \
    -v "$PWD"/sources:/root/ransomware:ro \
    -v "$PWD"/Downloads/TD:/root/truc.txt -v "$PWD"/Downloads/TD:/root/a.txt -v "$PWD"/token_data:/root/token \
    ransomware python /root/ransomware/ransomware.py \
    Downloads/TD/root/ransomware/truc.txt \
    Downloads/TD/root/ransomware/a.txt


