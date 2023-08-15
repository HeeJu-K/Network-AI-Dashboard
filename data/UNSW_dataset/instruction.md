Run this command to get the full data ([Reference](https://iotanalytics.unsw.edu.au/iottraces.html))

```bash
wget https://iotanalytics.unsw.edu.au/iottestbed/pcap/filelist.txt -O filelist.txt
cat filelist.txt | egrep -v "(^#.*|^$)" | xargs -n 1 wget
```

Once you finished downloading, makesure to unzip them all into `.pcap` files.