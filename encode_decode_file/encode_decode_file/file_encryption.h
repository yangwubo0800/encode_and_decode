// �����ļ��ӽ���״��Ļ���ֵ
#define ENCODE_FLAG 0x11223344
#define DECODE_FLAG 0x55667788
#define ORIGNAL_FILE 0x555555

// ������мӽ����������������
#define ENCRIPTION_FACTOR_ONE 0xab
#define ENCRIPTION_FACTOR_TWO 0xcd

/*
 ��¼�ļ��ӽ�������Ľṹ��
*/

typedef struct encript_flag
{
	int magic_number; // ������ǣ��ļ�״̬
	int count;        // ���ܴ����� ���Զ���𲽼��ܣ�������һ�ν����н������
}ENCRIPT_FLAG_S;
