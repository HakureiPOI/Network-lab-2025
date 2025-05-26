#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;

    // 检查 IP 报文长度是否合法
    if (buf->len < sizeof(ip_hdr_t))
        return;

    // 检查 IP 头部字段基本合法性
    if (ip_hdr->version != IP_VERSION_4 ||
        swap16(ip_hdr->total_len16) > buf->len ||
        ip_hdr->hdr_len < 5)
        return;

    // 验证 IP 头部校验和
    uint16_t hdr_checksum = ip_hdr->hdr_checksum16;
    ip_hdr->hdr_checksum16 = 0;
    if (hdr_checksum != checksum16((uint16_t *)ip_hdr, ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE))
        return;
    ip_hdr->hdr_checksum16 = hdr_checksum;

    // 仅处理发往本机的 IP 数据包
    if (memcmp(net_if_ip, ip_hdr->dst_ip, NET_IP_LEN) != 0)
        return;

    // 去除报文中多余的填充字段（若存在）
    if (buf->len > swap16(ip_hdr->total_len16))
        buf_remove_padding(buf, buf->len - swap16(ip_hdr->total_len16));

    // 提取源 IP 和上层协议类型
    uint8_t src_ip[NET_IP_LEN];
    memcpy(src_ip, ip_hdr->src_ip, NET_IP_LEN);
    uint8_t protocol = ip_hdr->protocol;

    // 若协议类型不支持，则返回 ICMP 协议不可达
    if (protocol != NET_PROTOCOL_ICMP && protocol != NET_PROTOCOL_UDP) {
        icmp_unreachable(buf, src_ip, ICMP_CODE_PROTOCOL_UNREACH);
        return;
    }

    // 去除 IP 头部，准备向上层协议传递
    buf_remove_header(buf, ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE);

    // 调用统一接口，将数据交由上层协议处理
    net_in(buf, protocol, src_ip);
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
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // 为 IP 头部预留空间
    buf_add_header(buf, sizeof(ip_hdr_t));
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;

    // 填写 IP 头部各字段
    ip_hdr->version = IP_VERSION_4;
    ip_hdr->hdr_len = 5;                     // 固定无选项字段
    ip_hdr->tos = 0;
    ip_hdr->total_len16 = swap16(buf->len);  // 报文总长度（含头部）
    ip_hdr->id16 = swap16(id);               // 分片标识

    // 设置标志位与偏移（含 MF 位）
    if (mf)
        ip_hdr->flags_fragment16 = swap16(IP_MORE_FRAGMENT | offset);
    else
        ip_hdr->flags_fragment16 = swap16(offset);

    ip_hdr->ttl = IP_DEFAULT_TTL;
    ip_hdr->protocol = protocol;
    ip_hdr->hdr_checksum16 = 0;

    // 设置源 IP 和目标 IP
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);

    // 计算并写入头部校验和
    uint16_t hdr_checksum = checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t));
    ip_hdr->hdr_checksum16 = hdr_checksum;

    // 调用 ARP 模块发送 IP 报文
    arp_out(buf, ip);
}


/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    static uint16_t ip_id = 0;

    // 若数据长度未超过 MTU（无需分片），直接发送
    if (buf->len <= ETHERNET_MAX_TRANSPORT_UNIT - 20) {
        ip_fragment_out(buf, ip, protocol, ip_id++, 0, 0);
        return;
    }

    uint16_t cur = 0;
    buf_t __fragment;
    buf_t *fragment = &__fragment;

    // 分片发送，每片最大负载为 1480 字节（1500 - 20）
    while (buf->len > 1480) {
        buf_init(fragment, 1480);
        memcpy(fragment->data, buf->data, 1480);
        buf_remove_header(buf, 1480);
        ip_fragment_out(fragment, ip, protocol, ip_id, cur / IP_HDR_OFFSET_PER_BYTE, 1);
        cur += 1480;
    }

    // 发送最后一个分片
    if (buf->len > 0) {
        buf_init(fragment, buf->len);
        memcpy(fragment->data, buf->data, buf->len);
        buf_remove_header(buf, buf->len);
        ip_fragment_out(fragment, ip, protocol, ip_id, cur / IP_HDR_OFFSET_PER_BYTE, 0);
    }

    ip_id++;
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}