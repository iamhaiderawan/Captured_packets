#include <pcap.h>
#include <iostream>
#include <netinet/ip.h>   // For IPv4 header
#include <netinet/ip6.h>  // For IPv6 header
#include <arpa/inet.h>    // For inet_ntop
#include <mysql/mysql.h>  // For MySQL

// Function to connect to MySQL database and create a database and table if not exists
MYSQL* init_db() {
    MYSQL *conn = mysql_init(nullptr);

    if (conn == nullptr) {
        std::cerr << "mysql_init() failed\n";
        return nullptr;
    }

    // Connect to MySQL with the provided username and password
    if (mysql_real_connect(conn, "localhost", "root", "12345", nullptr, 0, nullptr, 0) == nullptr) {
        std::cerr << "mysql_real_connect() failed\n" << mysql_error(conn) << std::endl;
        mysql_close(conn);
        return nullptr;
    }

    // Create the database if it doesn't exist
    if (mysql_query(conn, "CREATE DATABASE IF NOT EXISTS packetDB")) {
        std::cerr << "CREATE DATABASE failed: " << mysql_error(conn) << std::endl;
        mysql_close(conn);
        return nullptr;
    }

    // Select the database
    if (mysql_query(conn, "USE packetDB")) {
        std::cerr << "USE packetDB failed: " << mysql_error(conn) << std::endl;
        mysql_close(conn);
        return nullptr;
    }

    // Create the table if it doesn't exist
    const char *create_table_query = "CREATE TABLE IF NOT EXISTS packets ("
                                     "id INT AUTO_INCREMENT PRIMARY KEY, "
                                     "src_ip VARCHAR(45), "
                                     "dst_ip VARCHAR(45), "
                                     "ip_version VARCHAR(10), "
                                     "timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)";
    
    if (mysql_query(conn, create_table_query)) {
        std::cerr << "CREATE TABLE failed: " << mysql_error(conn) << std::endl;
        mysql_close(conn);
        return nullptr;
    }

    return conn;
}

// Function to insert packet data into the database
void insert_packet_to_db(MYSQL *conn, const char *src_ip, const char *dst_ip, const char *ip_version) {
    std::string query = "INSERT INTO packets (src_ip, dst_ip, ip_version) VALUES ('";
    query += src_ip;
    query += "', '";
    query += dst_ip;
    query += "', '";
    query += ip_version;
    query += "')";
    
    if (mysql_query(conn, query.c_str())) {
        std::cerr << "INSERT failed: " << mysql_error(conn) << std::endl;
    }
}

// Packet handler for processing packets and saving them to the database
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    MYSQL *conn = (MYSQL *)user_data;  // MySQL connection passed as user_data

    // Ethernet headers are not available on the lo interface, so skip to IP headers
    const struct ip *ip_header = (struct ip *)(packet + 16); // Skip Linux cooked-mode capture header (16 bytes)

    if (ip_header->ip_v == 4) {
        // IPv4 packet
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        std::cout << "IPv4 Packet: Src: " << src_ip << ", Dst: " << dst_ip << std::endl;

        // Save to database
        insert_packet_to_db(conn, src_ip, dst_ip, "IPv4");
    
    } else if (ip_header->ip_v == 6) {
        // IPv6 packet
        const struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + 16);
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

        std::cout << "IPv6 Packet: Src: " << src_ip << ", Dst: " << dst_ip << std::endl;

        // Save to database
        insert_packet_to_db(conn, src_ip, dst_ip, "IPv6");
    }
}

int main() {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("lo", BUFSIZ, 1, 1000, error_buffer);

    if (handle == nullptr) {
        std::cerr << "Failed to open device: " << error_buffer << std::endl;
        return 1;
    }

    // Initialize the MySQL database and create the table
    MYSQL *conn = init_db();
    if (conn == nullptr) {
        return 1;  // Exit if unable to connect to database
    }

    // Capture packets in an infinite loop, passing the MySQL connection to the handler
    pcap_loop(handle, 0, packet_handler, (u_char *)conn);

    pcap_close(handle);
    mysql_close(conn);  // Close MySQL connection

    return 0;
}
