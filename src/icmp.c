#include "icmp.h"

#include "ip.h"
#include "net.h"

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip)
{
    // 初始化发送缓冲区，长度与接收到的请求报文一致
    buf_init(&txbuf, req_buf->len);
    memcpy(txbuf.data, req_buf->data, req_buf->len);

    // 获取请求报文中的 ICMP 头部
    icmp_hdr_t *req_icmp_hdr = (icmp_hdr_t *)req_buf->data;

    // 构造 ICMP 回显应答报文头部
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;
    icmp_hdr->type = ICMP_TYPE_ECHO_REPLY;  // 类型设为 Echo Reply（0）
    icmp_hdr->code = 0;                     // Code 固定为 0
    icmp_hdr->checksum16 = 0;              // 校验和初始化为 0
    icmp_hdr->id16 = req_icmp_hdr->id16;   // 拷贝标识符
    icmp_hdr->seq16 = req_icmp_hdr->seq16; // 拷贝序列号

    // 计算并填写校验和
    icmp_hdr->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);

    // 通过 IP 层发送 ICMP 数据报
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    // 检查 ICMP 报文长度是否合法（至少应包含完整头部）
    if (buf->len < sizeof(icmp_hdr_t))
        return;

    // 解析 ICMP 报文头部
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)buf->data;

    // 若为 Echo Request 类型，处理回显请求
    if (icmp_hdr->type == ICMP_TYPE_ECHO_REQUEST && icmp_hdr->code == 0)
        icmp_resp(buf, src_ip);
}


/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{
    // 构造 ICMP 数据部分，包含原始 IP 头部和其后 8 字节数据
    buf_init(&txbuf, sizeof(ip_hdr_t) + 8);
    memcpy(txbuf.data, recv_buf->data, sizeof(ip_hdr_t) + 8);

    // 在前方添加 ICMP 头部空间
    buf_add_header(&txbuf, sizeof(icmp_hdr_t));

    // 填写 ICMP 报文头部字段
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;
    icmp_hdr->type = ICMP_TYPE_UNREACH; // 类型为不可达
    icmp_hdr->code = code;              // 指定不可达原因
    icmp_hdr->checksum16 = 0;
    icmp_hdr->id16 = 0;
    icmp_hdr->seq16 = 0;

    // 计算并填写校验和
    icmp_hdr->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);

    // 发送 ICMP 差错报文
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}


/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}