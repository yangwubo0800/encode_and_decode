// 定义文件加解密状体的幻数值
#define ENCODE_FLAG 0x11223344
#define DECODE_FLAG 0x55667788
#define ORIGNAL_FILE 0x555555

// 定义进行加解密运算的运算因子
#define ENCRIPTION_FACTOR_ONE 0xab
#define ENCRIPTION_FACTOR_TWO 0xcd

/*
 记录文件加解密情况的结构体
*/

typedef struct encript_flag
{
	int magic_number; // 幻数标记，文件状态
	int count;        // 加密次数， 可以多次逐步加密，解密则一次将所有解密完成
}ENCRIPT_FLAG_S;
