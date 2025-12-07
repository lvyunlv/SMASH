perl -e 'print pack("Q<", 6) x 1' > Input-P.bin

bash -c 'n=393216; for ((i=0;i<n;i++)); do echo $((RANDOM % 11)); done' > Input-P.txt
