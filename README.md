# Captured_packets
Simple application that inputs traffic from an interface, process it and stores source and destination IP, check if it is IPV6 or IPV4 and stores it in the database(mysql).

Here in this code a pcap in running on lo interface. it is a loop back interface which throw live traffic on an iterface.
Than this traffic is captured and we parse few details like ip's of both destination and source, and ip version.
we also parse the time stamp.
After fetching these parameters we save these to mysql database.
