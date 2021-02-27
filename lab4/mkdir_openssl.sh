dir=./demoCA
certs=$dir/certs
crl_dir=$dir/crl
new_certs_dir=$dir/newcerts

database=$dir/index.txt
serial=$dir/serial

for directory in $dir $certs $crl_dir $new_certs_dir
do
    echo "mkdir -p $directory"
    mkdir -p $directory
done

touch $database
echo 1000 > $serial