#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "file_encryption.h"



/*
  ���������� ��ȡ�ļ�����󼸸��ֽ�
  �������:  file_name �����ļ���
  �������:	 param �ļ��ӽ��ܱ��

  ����ֵ : �ɹ�����0
		: ʧ�ܷ��� -1
*/

int read_file_flag(char *file_name, ENCRIPT_FLAG_S *parma)
{
	FILE *fd;
	int ret;
	int flag_size = sizeof(ENCRIPT_FLAG_S);
	int file_size;
	char read_buf[8];
	// �����ļ���ǵı���
	ENCRIPT_FLAG_S *file_flag = parma;


	fd = fopen(file_name, "a+");
	if(fd <0)
	{
		printf("open the file failed, please input the right file name\n");
		return -1;
	}

	//��λ�ļ�����β
	ret = fseek(fd, 0, SEEK_END);
	if(ret < 0)
	{
		printf("seek file failed\n");
		return -1;
	}
	
	//�����ļ���С,���ļ���СС�ڼ�¼���ʱ��һ����û�о����κδ�����ļ�
	file_size = ftell(fd) ;
	if(file_size < flag_size)
	{
		file_flag->magic_number = ORIGNAL_FILE;
		file_flag->count = 0;
		fclose(fd);
		return 0;
	}
	
	printf("----------read flag -flag_size=%d\n", -flag_size);
	// ��λ���ļ�����Ǵ�С���ֽڣ����ж�ȡ��ֵ
	ret = fseek(fd,  -flag_size, SEEK_END);
	if(ret < 0)
	{
		printf("seek file failed\n");
		fclose(fd);
		return -1;
	}
	
	memset(read_buf, 0, 8);
	ret = fread(read_buf, flag_size,1, fd);
	if(ret < 0)
	{
		printf("read file failed\n");
		fclose(fd);
		return -1;
	}

		printf("#####################read flag###############\n");
		int i;

		for(i=0; i<8; i++)
		{
			printf("%#x  ", read_buf[i]);
		}
	
	// ����ȡ���ı��ֵ���и�ֵ,����ע���С�ˣ�X86�Ǵ��
	file_flag->magic_number = read_buf[3]<<24 | read_buf[2] << 16 | read_buf[1]<< 8 | read_buf[0] ;
	 
	file_flag->count = read_buf[7]<<24 | read_buf[6] << 16 | read_buf[5]<< 8 | read_buf[4] ;
	
	fclose(fd);

	return 0;

}


/*
*  ��������: ���ļ����м���
   �������:  �ļ��ļӽ��ܱ��parm
			  �ļ��� file_name
   ����ֵ:  �ɹ�����0
		   ʧ�ܷ���-1
*/
int encode_file(ENCRIPT_FLAG_S* param , char * file_name)
{
	FILE* fd;
	//��Ҫд���ļ��ļӽ��ܱ��
	char temp_flag[8];
	ENCRIPT_FLAG_S flag;
	int ret;
	int file_size;
	char *read_file_buf;
	int calc_count;  /*ԭʼ�ļ���ʵ�ʴ�С��Ҳ��Ҫ�������������ֽ���*/
	int i;
	char calc_factor; /*�����������*/

	fd = fopen(file_name, "a+");
	if(fd <0)
	{
		printf("open the file failed, please input the right file name\n");
		return -1;
	}


	// ���ļ����е����ݶ������ŵ�һ���ڴ��У������ļ����Ƿǳ���
	ret = fseek(fd, 0, SEEK_END);
	if(ret < 0)
	{
		printf("encode file seek failed\n");
		fclose(fd);
		return -1;
	}
	
	// �����ļ���С�������ӽ����ֽ�
	file_size = ftell(fd);
	printf("the -------------totoal file size is %d\n",file_size);

	// ���ڷ�ԭʼ�ļ������˸��ֽ��Ǳ���ֽڣ���������
	if(param->magic_number != ORIGNAL_FILE)
	{
		calc_count = file_size - sizeof(ENCRIPT_FLAG_S);
		printf("-------calc_count= %d\n",calc_count);
		// �Ѿ����й�ż�μ�������ģ�ʹ�õ�һ���������ӽ���������㣻���й������μ��ܵģ���ʹ�õڶ�����������
		if(param->count % 2 == 0)
		{
			calc_factor = ENCRIPTION_FACTOR_ONE;
		}
		else
		{
			calc_factor = ENCRIPTION_FACTOR_TWO;
		}
	}
	else // ԭʼ�ļ�����û�н��й����ܵ��ļ���ʹ�õ�һ������
	{
		calc_count = file_size;
		calc_factor = ENCRIPTION_FACTOR_ONE;
	}
	printf("-------------calc count=%d\n",calc_count);
	// ����ԭʼ�ļ���С���ֽڿռ�
	read_file_buf = (char *)malloc(calc_count);
	// ��λ���ļ���ͷ�����ж�ȡ
	ret = fseek(fd, 0, SEEK_SET);
	if(ret < 0)
	{
		printf("encode file seek file failed\n");
		fclose(fd);
		return -1;
	}
	printf("-------------calc count=%d\n",calc_count);
	ret = fread(read_file_buf, calc_count, 1, fd);
	if(ret < 0)
	{
		printf("encode file read file failed\n");
		fclose(fd);
		return -1;
	}
	printf("-------------calc count=%d\n",calc_count);
	// ���ļ���ÿ���ֽڽ����������
	for(i=0; i<calc_count; i++)
	{
		printf("read_buf[%d]=%d  \n", i , read_file_buf[i]);
		read_file_buf[i]^=calc_factor;
		printf("after calc read_buf[%d]=%d  \n", i , read_file_buf[i]);
	}

	//��������ȹر��ļ���Ȼ����w+ ��ʽ�ٴδ򿪣������������½��ļ�����д�뵽ԭ��λ�ã�������׷�ӵ�ĩβ

	fclose(fd);

	fd = fopen(file_name, "w+");
	if(ret < 0)
	{
		printf("encode file open file failed\n");
		return -1;
	}


	int temp_size0 = ftell(fd);
	printf("~~~~~~~~~~~~~~ the encode file size is %d\n",temp_size0);



	// ��λ����ͷ����������ļ�������д��
	ret = fseek(fd, 0, SEEK_SET);
	if(ret < 0)
	{
		printf("encode file seek file failed\n");
		return -1;
	}


	int temp_size3 = ftell(fd);
	printf("~~~~~~~~~~~~~~ the encode file size is %d  calc_count=%d\n",temp_size3, calc_count);

	ret = fwrite(read_file_buf, calc_count, 1, fd);


	int temp_size = ftell(fd);
	printf("~~~~~~~~~~~~~~ the encode file size is %d\n",temp_size);



	if(ret < 0)
	{
		printf("encode file write file failed\n");
		return -1;
	}

	// �ͷ��ڴ�
	free(read_file_buf);

	//������һ�κ󣬽����ܱ��д���ļ�ĩβ
	flag.magic_number = ENCODE_FLAG;
	flag.count = param->count +1;
	memcpy(temp_flag, &flag, sizeof(ENCRIPT_FLAG_S));
	
	//��λ���ļ���β��д����
	ret = fseek(fd, 0 , SEEK_END);
	if(ret < 0)
	{
		printf("encode file write file flag failed\n");
		fclose(fd);
		return -1;
	}

	fwrite(temp_flag, sizeof(ENCRIPT_FLAG_S),1,fd);
	if(ret < 0)
	{
		printf("encode file write file flag failed\n");
		fclose(fd);
		return -1;
	}


	int temp_size2 = ftell(fd);
	printf("~~~~~~~~~~~~~~ the encode file size is %d\n",temp_size2);

	fclose(fd);
	
	return 0;
}


/*
*  ��������: ���ļ����н���
   �������:  �ļ��ļӽ��ܱ��parm
			  �ļ��� file_name
   ����ֵ:  �ɹ�����0
		   ʧ�ܷ���-1
*/
int decode_file(ENCRIPT_FLAG_S* param, char * file_name)
{
	int ret;
	FILE* fd;
	int file_size;
	int original_file_size;
	bool flag_choose_factor = false;
	char *read_file_buf;
	//��Ҫд���ļ��ļӽ��ܱ��
	char temp_flag[8];
	ENCRIPT_FLAG_S flag;

	fd = fopen(file_name, "a+");
	if(fd <0)
	{
		printf("open the file failed, please input the right file name\n");
		return -1;
	}


	// ���ļ����е����ݶ������ŵ�һ���ڴ��У������ļ����Ƿǳ���
	ret = fseek(fd, 0, SEEK_END);
	if(ret < 0)
	{
		printf("encode file seek failed\n");
		fclose(fd);
		return -1;
	}
	
	// �����ļ���С�������ӽ����ֽ�
	file_size = ftell(fd);
	original_file_size = file_size - sizeof(ENCRIPT_FLAG_S);


	printf("~~~~~~~~~~~~~~~~~~~~~decode original_file_size is %d\n",original_file_size);

	// ����ԭʼ�ļ���С���ֽڿռ�
	read_file_buf = (char *)malloc(original_file_size);

	// ��λ���ļ���ͷ�����ж�ȡ
	ret = fseek(fd, 0, SEEK_SET);
	if(ret < 0)
	{
		printf("encode file seek file failed\n");
		fclose(fd);
		return -1;
	}

	ret = fread(read_file_buf, original_file_size, 1, fd);
	if(ret < 0)
	{
		printf("encode file read file failed\n");
		fclose(fd);
		return -1;
	}
	

	int decode_size0 = ftell(fd);
	printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~after read decode size is %d\n",decode_size0);



	// �ж��ļ��еļ��ܴ�����ѡ�������ĸ���������

	if(param->count % 2 == 0)
	{
		flag_choose_factor = false;
	}
	else
	{
		flag_choose_factor = true;
	}



	int m,k;
	// ѭ���ֻ�ʹ���������ӽ���������㣬ֻ��Ҫȷ����������һ��
	for(m=0; m<param->count; m++)
	{
		if(flag_choose_factor) // �����μ��ܣ����õ�һ������
		{
			// �������ֽڶ������������һ��
			for(k=0; k<original_file_size; k++)
			{
				read_file_buf[k]^= ENCRIPTION_FACTOR_ONE;
			}
			flag_choose_factor = false;
		}
		else  // ż���μ��ܣ��õڶ�������
		{
			for(k=0; k<original_file_size; k++)
			{
				read_file_buf[k]^= ENCRIPTION_FACTOR_TWO;
			}
			flag_choose_factor = true;
		}
	}


		//��������ȹر��ļ���Ȼ����w+ ��ʽ�ٴδ򿪣������������½��ļ�����д�뵽ԭ��λ�ã�������׷�ӵ�ĩβ

	fclose(fd);

	fd = fopen(file_name, "w+");
	if(ret < 0)
	{
		printf("encode file open file failed\n");
		return -1;
	}

	// ��λ����ͷ����������ļ�������д��
	ret = fseek(fd, 0, SEEK_SET);
	if(ret < 0)
	{
		printf("encode file seek file failed\n");
		return -1;
	}



	int decode_size1 = ftell(fd);
	printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~after read decode size is %d\n",decode_size1);




	ret = fwrite(read_file_buf, original_file_size, 1, fd);
	if(ret < 0)
	{
		printf("encode file write file failed\n");
		return -1;
	}



	int decode_size2 = ftell(fd);
	printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~after read decode size is %d\n",decode_size2);

	// �ͷ��ڴ�
	free(read_file_buf);

	
	//������󣬽��ӽ��ܱ��д���ļ�ĩβ
	flag.magic_number = DECODE_FLAG;
	flag.count = 0;
	memcpy(temp_flag, &flag, sizeof(ENCRIPT_FLAG_S));
	
	//��λ���ļ���β��д����
	ret = fseek(fd, 0 , SEEK_END);
	if(ret < 0)
	{
		printf("encode file write file flag failed\n");
		fclose(fd);
		return -1;
	}

	fwrite(temp_flag, sizeof(ENCRIPT_FLAG_S),1,fd);
	if(ret < 0)
	{
		printf("encode file write file flag failed\n");
		return -1;
	}


	int decode_size3 = ftell(fd);
	printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~after read decode size is %d\n",decode_size3);

	fclose(fd);

	return 0;
}



/*
	�������������� ��ȡ�������������
				   ���ݲ�����ȡ�ļ�������ֽڣ����м��ܻ��߽���
*/
int main(int argc , char * argv[])
{
	int ret;
	char *command;
	char *file_name;
	ENCRIPT_FLAG_S file_flag;
	bool encode_opt = false;
	bool decode_opt = false;
	int user_input;


	
	// �жϲ�����������Ƿ���ȷ
	if(argc != 3)
	{
		printf(" please input the right parm\n");
		return 0;
	}

	command = argv[1];
	printf("the argv is %s  command is %s\n",argv[1], command);
	file_name = argv[2];

	//�жϲ��������Ƿ���ȷ
	encode_opt = (strcmp(command, "encode") == 0);
	decode_opt = (strcmp(command, "decode") == 0);

	if((!encode_opt) && (!decode_opt))
	{
		printf("your input command is wrong ,please input the rigth command\n");
		return 0;
	}
	
	// ��������������ȷ������Խ����ļ�����ǲ���
	ret = read_file_flag(file_name, &file_flag);
	printf("1main---------magic=%#x\n", file_flag.magic_number);

	if(ret == 0)
	{

		// ����ԭʼû�н��д�����ļ�����ȡ����������δ֪�ģ�Ҫ���ļ�״̬����ת������
		if((file_flag.magic_number != ENCODE_FLAG)&&(file_flag.magic_number != DECODE_FLAG))
		{
			file_flag.magic_number = ORIGNAL_FILE;
			file_flag.count = 0;
		}
		printf("2main---------magic=%#x\n", file_flag.magic_number);

		if(encode_opt)
		{
			// �����ļ�״̬��ʾ�Ƿ���Ҫ����

			// �ж��ļ��ļ��ܴ������Ѿ����ܽ�����ʾ���Ƿ�Ҫ���ܣ�����������ܣ�����ֱ���˳�
			if(file_flag.magic_number == ENCODE_FLAG)
			{
				printf("the file is alread encoded,would you like to encode it again?\n");
				printf("if you think so ,please input y ,else please input n\n");
				// ��׽�û�����İ���
				user_input = getchar();
				if(user_input == 'n')
				{
					printf("the file is already encripted, so we won't do it again!\n");
					return 0;
				}
			}
			printf("3main---------magic=%#x\n", file_flag.magic_number);

			encode_file(&file_flag, file_name);

		}
		else if(decode_opt) 
		{
			// �����ļ�״̬��ʾ�ļ��Ƿ���Ҫ����
			if(file_flag.magic_number != ENCODE_FLAG)
			{
				printf("the file is not encripted, it is not need to decode !\n");
				return 0;
			}
			else
			{
				decode_file(&file_flag, file_name);
			}
		}
		else
		{
			printf("the commond is wrong!");
		}
	}
	else
	{
		printf("the file opration failed\n");
	}
	
	return 0;
	

}