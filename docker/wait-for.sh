max_retry=$2
counter=0
while ! docker image inspect $1
do
  [[ counter -eq $max_retry ]] && echo "Failed!" && exit 1		
  ((counter++))
  echo "Sleep a little(1m)."
  sleep 1m
  echo "Now try again."
done
