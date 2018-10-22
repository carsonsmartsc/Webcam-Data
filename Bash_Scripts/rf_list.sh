#!/bin/bash
# read file line by line
# $line is a list, process it as list and extract words
input=test.txt

while read -r line
do
    	echo "Line: $line"
	for word in $line
	do
    		echo "Word: $word"
	done
done < "$input"
