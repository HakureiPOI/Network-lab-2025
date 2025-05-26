#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include <stdio.h>
#include <string.h>

/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    // 初始化发送缓冲区
    buf_init(&txbuf, sizeof(arp_pkt_t));
    arp_pkt_t *pkt = (arp_pkt_t *)txbuf.data;

    // 使用初始模板填充通用字段
    memcpy(pkt, &arp_init_pkt, sizeof(arp_pkt_t));

    // 设置操作类型为ARP请求（opcode = 1）
    pkt->opcode16 = swap16(ARP_REQUEST);

    // 设置目标IP地址
    memcpy(pkt->target_ip, target_ip, NET_IP_LEN);

    // 目标MAC设置为广播地址，ARP请求使用广播方式发送
    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    // 初始化发送缓冲区
    buf_init(&txbuf, sizeof(arp_pkt_t));
    arp_pkt_t *pkt = (arp_pkt_t *)txbuf.data;

    // 使用初始模板填充通用字段
    memcpy(pkt, &arp_init_pkt, sizeof(arp_pkt_t));

    // 设置操作类型为ARP响应（opcode = 2）
    pkt->opcode16 = swap16(ARP_REPLY);

    // 设置目标IP和目标MAC（即对方地址）
    memcpy(pkt->target_ip, target_ip, NET_IP_LEN);
    memcpy(pkt->target_mac, target_mac, NET_MAC_LEN);

    // 单播发送ARP响应
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    // 数据包长度校验
    if (buf->len < sizeof(arp_pkt_t)) return;

    arp_pkt_t *pkt = (arp_pkt_t *)buf->data;

    // 校验ARP报文格式是否合法
    if (swap16(pkt->hw_type16) != ARP_HW_ETHER ||
        swap16(pkt->pro_type16) != NET_PROTOCOL_IP ||
        pkt->hw_len != NET_MAC_LEN ||
        pkt->pro_len != NET_IP_LEN) return;

    // 更新ARP表（记录对方IP与MAC）
    map_set(&arp_table, pkt->sender_ip, pkt->sender_mac);

    // 检查是否有等待该IP地址回复的缓存包
    void *cached_buf = map_get(&arp_buf, pkt->sender_ip);
    if (cached_buf) {
        // 发送缓存数据包
        ethernet_out(cached_buf, pkt->sender_mac, NET_PROTOCOL_IP);
        // 删除缓存项
        map_delete(&arp_buf, pkt->sender_ip);
    }

    // 如果是ARP请求，且目标IP为本机IP，则发送ARP响应
    if (swap16(pkt->opcode16) == ARP_REQUEST &&
        memcmp(pkt->target_ip, net_if_ip, NET_IP_LEN) == 0) {
        arp_resp(pkt->sender_ip, pkt->sender_mac);
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    // 查询ARP表中是否存在对应MAC地址
    uint8_t *mac = map_get(&arp_table, ip);

    if (mac) {
        // 若找到MAC，直接发送
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
    } else {
        // 未找到MAC，检查是否已缓存该IP的包
        if (!map_get(&arp_buf, ip)) {
            // 若尚未发送ARP请求，缓存数据包并发出ARP请求
            map_set(&arp_buf, ip, buf);
            arp_req(ip);
        }
        // 否则等待前一个ARP请求响应，无需重复发送
    }
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}