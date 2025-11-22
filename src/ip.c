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
    } else if (buf->len > swap16(((ip_hdr_t *)buf->data)->total_len16)) {
        /* If the buffer length is greater than the total length, remove padding */
        buf_remove_padding(buf, buf->len - swap16(((ip_hdr_t *)buf->data)->total_len16));
    }
    
    /* Save protocol and source ip, then remove ip header. */
    uint8_t protocol = ((ip_hdr_t *)buf->data)->protocol;
    uint8_t src_ip[NET_IP_LEN];
    memcpy(src_ip, ((ip_hdr_t *)buf->data)->src_ip, NET_IP_LEN);
    buf_remove_header(buf, ((ip_hdr_t *)buf->data)->hdr_len * IP_HDR_LEN_PER_BYTE);

    if (net_in(buf, protocol, src_ip) == -1) {
        /* If there is no handler for the protocol, send an ICMP unreachable message */
        icmp_unreachable(buf, src_ip, ICMP_CODE_PROTOCOL_UNREACH);
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
    /* Add ip header. */
    buf_add_header(buf, sizeof(ip_hdr_t));
    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;
    
    /* Fill in the IP header fields */
    hdr->version = IP_VERSION_4;
    hdr->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;
    hdr->tos = 0;
    hdr->total_len16 = swap16(buf->len);
    hdr->id16 = swap16(id);
    
    /* Set flags_fragment and offset. */
    uint16_t flags_fragment = (offset / IP_HDR_OFFSET_PER_BYTE) & 0x1FFF;  // 偏移量占低13位
    if (mf) {
        flags_fragment |= IP_MORE_FRAGMENT;  // 设置MF标志位
    }
    hdr->flags_fragment16 = swap16(flags_fragment);
    
    hdr->ttl = IP_DEFALUT_TTL;
    hdr->protocol = protocol;
    memcpy(hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(hdr->dst_ip, ip, NET_IP_LEN);
    
    /* Calculate checksum */
    hdr->hdr_checksum16 = 0;
    hdr->hdr_checksum16 = checksum16((uint16_t *)hdr, sizeof(ip_hdr_t));
    
    /* Send to arp level. */
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    // 计算MTU，去掉IP头部的空间
    size_t max_payload = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);
    
    if (buf->len > max_payload) {
        // 需要分片
#ifdef TEST
        int id = 0;  // 测试环境使用固定ID
#else
        int id = rand() % UINT16_MAX;
#endif
        size_t fragment_size = max_payload & ~7;  // 必须是8的倍数
        size_t sent = 0;
        
        while (sent < buf->len) {
            size_t this_fragment_size = buf->len - sent;
            int mf = 0;
            
            if (this_fragment_size > fragment_size) {
                this_fragment_size = fragment_size;
                mf = 1;  // 还有更多分片
            }
            
            // 创建分片缓冲区
            buf_t fragment;
            buf_init(&fragment, this_fragment_size);
            memcpy(fragment.data, buf->data + sent, this_fragment_size);
            
            // 发送分片
            ip_fragment_out(&fragment, ip, protocol, id, sent, mf);
            
            sent += this_fragment_size;
        }
    } else {
        // 不需要分片，直接发送
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