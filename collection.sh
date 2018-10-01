sleep 5
end=$(( $(date +%s) + 300 ))
while [ $(date +%s) -lt $end ]
do
	top -b -n 1 >> ./www/top_data_webcam.txt
	date -u >> ./www/date_data_webcam.txt
	ps -w >> ./www/ps_data_webcam.txt
	netstat -aelptuwx >> ./www/netstat_data_webcam.txt
	sleep 1
done
ping -c 5 192.168.10.11
