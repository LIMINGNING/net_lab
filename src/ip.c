#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"
#include <stdlib.h>
#include <string.h>

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    /* Check the length of the buffer */
    if (buf->len < sizeof(ip_hdr_t)) {
        return;
    }

    /* If the IP header is invalid, drop the packet */
    if ((((ip_hdr_t *)buf->data)->version) != IP_VERSION_4 || (((ip_hdr_t *)buf->data)->hdr_len * IP_HDR_LEN_PER_BYTE) < sizeof(ip_hdr_t)) {
        return;
    }

    /* Calculate the checksum */
    uint16_t temp_checksum = ((ip_hdr_t *)buf->data)->hdr_checksum16;
    ((ip_hdr_t *)buf->data)->hdr_checksum16 = 0;
    /* The reason why /2 is that we are working with 16-bit words */
    uint16_t data[IP_HDR_LEN_PER_BYTE * ((ip_hdr_t *)buf->data)->hdr_len / 2]; /* Remember to transform the data */
    for (size_t i = 0; i < sizeof(data) / sizeof(data[0]); i++) {
        data[i] = ((uint16_t *)buf->data)[i];
    }
    if (checksum16(data, ((ip_hdr_t *)buf->data)->hdr_len * IP_HDR_LEN_PER_BYTE) == temp_checksum) {
        /* If the checksum is valid, process the packet */
        ((ip_hdr_t *)buf->data)->hdr_checksum16 = temp_checksum;
    } else {
        /* If the checksum is invalid, drop the packet */
        return;
    }

    if (memcmp(((ip_hdr_t *)buf->data)->dst_ip, net_if_ip, NET_IP_LEN) != 0) {
        /* If the destination IP address is not equal to the interface IP address, drop the packet */
        return;
    }

    if (buf->len < swap16(((ip_hdr_t *)buf->data)->total_len16)) {
        /* If the buffer length is less than the total length, drop the packet */
        return;
    } else {
        buf_remove_padding(buf, buf->len - swap16(((ip_hdr_t *)buf->data)->total_len16));
    }

    buf_remove_padding(buf, buf->len - swap16(((ip_hdr_t *)buf->data)->total_len16));

    if (net_in(buf, ((ip_hdr_t *)buf->data)->protocol, ((ip_hdr_t *)buf->data)->src_ip) == -1) {
        /* If there is no handler for the protocol, send an ICMP unreachable message */
        icmp_unreachable(buf, src_mac, ICMP_CODE_PROTOCOL_UNREACHABLE);
    }

    return;
}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {

}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    if (buf->len + sizeof(ip_hdr_t) > 1500) {
        buf_t *txbuf = malloc(sizeof(buf_t));
        buf_init(txbuf, 1500 - sizeof(ip_hdr_t));

        int id = rand() % UINT16_MAX;

        uint16_t offset = 0;
        int pacage_id = 0;

        size_t original_len = buf->len;
        while (original_len - 1480 > 0) {
            offset = pacage_id * 1480 / 8;
            ip_fragment_out(txbuf, ip, protocol, id, offset, 1);
            original_len -= 1480;
            pacage_id++;
        }

        if (original_len > 0) {
            buf_t *txbuf1 = malloc(sizeof(buf_t));
            buf_init(txbuf1, original_len);
            offset = pacage_id * 1480 / 8;
            ip_fragment_out(txbuf1, ip, protocol, id, offset, 0);
        }
    } else {
        ip_fragment_out(buf, ip, protocol, rand() % UINT16_MAX, 0, 0);
    }

}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}