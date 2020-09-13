DEST=/data/int2int/2020
for dir in *; do 
  cd $dir
  for file in *; do
    timestamp=$(echo $file | cut -f 2 -d .)
    month=$(date --date="@$timestamp" "+%m")
    day=$(date --date="@$timestamp" "+%d")
    hour=$(date --date="@$timestamp" "+%H")
    directory=$DEST/$month/$day
    mkdir -p $directory
    rwp2yaf2silk --in=$file --out=- | rwappend --create $directory/int2int-Internal_2020$month$day.$hour -
    echo Finished $month/$day, hour $hour
  done
  cd ..
done
