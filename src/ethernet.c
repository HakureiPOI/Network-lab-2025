#include "ethernet.h"

#include "arp.h"
#include "driver.h"
#include "ip.h"
#include "utils.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf) {
    // 判断数据包是否小于以太网头部长度
    if (buf->len < sizeof(ether_hdr_t)) {
        return;
    }

    // 提取以太网帧头部
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;

    // 检查目的 MAC 地址是否为本机或广播地址
    if (memcmp(hdr->dst, net_if_mac, NET_MAC_LEN) != 0 &&
        memcmp(hdr->dst, ether_broadcast_mac, NET_MAC_LEN) != 0) {
        return;
    }

    // 提取上层协议字段并转换为主机字节序
    uint16_t protocol = swap16(hdr->protocol16);

    // 移除以太网包头
    buf_remove_header(buf, sizeof(ether_hdr_t));

    // 将数据包交给上层协议处理
    net_in(buf, protocol, hdr->src);
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol) {
    // 填充到最小长度
    if (buf->len < ETHERNET_MIN_TRANSPORT_UNIT) {
        buf_add_padding(buf, ETHERNET_MIN_TRANSPORT_UNIT - buf->len);
    }

    // 添加以太网头部
    buf_add_header(buf, sizeof(ether_hdr_t));
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;

    // 填写目的地址、源地址、协议类型
    memcpy(hdr->dst, mac, NET_MAC_LEN);
    memcpy(hdr->src, net_if_mac, NET_MAC_LEN);
    hdr->protocol16 = swap16(protocol);

    // 发送帧
    driver_send(buf);
}

/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init() {
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll() {
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
