#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "file_encryption.h"



/*
  函数描述： 读取文件的最后几个字节
  输入参数:  file_name 加密文件名
  输出参数:	 param 文件加解密标记

  返回值 : 成功返回0
		: 失败返回 -1
*/

int read_file_flag(char *file_name, ENCRIPT_FLAG_S *parma)
{
	FILE *fd;
	int ret;
	int flag_size = sizeof(ENCRIPT_FLAG_S);
	int file_size;
	char read_buf[8];
	// 返回文件标记的变量
	ENCRIPT_FLAG_S *file_flag = parma;


	fd = fopen(file_name, "a+");
	if(fd <0)
	{
		printf("open the file failed, please input the right file name\n");
		return -1;
	}

	//定位文件到结尾
	ret = fseek(fd, 0, SEEK_END);
	if(ret < 0)
	{
		printf("seek file failed\n");
		return -1;
	}
	
	//计算文件大小,当文件大小小于记录标记时，一定是没有经过任何处理的文件
	file_size = ftell(fd) ;
	if(file_size < flag_size)
	{
		file_flag->magic_number = ORIGNAL_FILE;
		file_flag->count = 0;
		fclose(fd);
		return 0;
	}
	
	printf("----------read flag -flag_size=%d\n", -flag_size);
	// 定位到文件最后标记大小的字节，进行读取赋值
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
	
	// 将读取到的标记值进行赋值,还得注意大小端，X86是大端
	file_flag->magic_number = read_buf[3]<<24 | read_buf[2] << 16 | read_buf[1]<< 8 | read_buf[0] ;
	 
	file_flag->count = read_buf[7]<<24 | read_buf[6] << 16 | read_buf[5]<< 8 | read_buf[4] ;
	
	fclose(fd);

	return 0;

}


/*
*  函数功能: 对文件进行加密
   输入参数:  文件的加解密标记parm
			  文件名 file_name
   返回值:  成功返回0
		   失败返回-1
*/
int encode_file(ENCRIPT_FLAG_S* param , char * file_name)
{
	FILE* fd;
	//将要写入文件的加解密标记
	char temp_flag[8];
	ENCRIPT_FLAG_S flag;
	int ret;
	int file_size;
	char *read_file_buf;
	int calc_count;  /*原始文件的实际大小，也即要进行异或运算的字节数*/
	int i;
	char calc_factor; /*异或运算因子*/

	fd = fopen(file_name, "a+");
	if(fd <0)
	{
		printf("open the file failed, please input the right file name\n");
		return -1;
	}


	// 将文件所有的内容读出来放到一块内存中，假设文件不是非常大
	ret = fseek(fd, 0, SEEK_END);
	if(ret < 0)
	{
		printf("encode file seek failed\n");
		fclose(fd);
		return -1;
	}
	
	// 整个文件大小，包括加解密字节
	file_size = ftell(fd);
	printf("the -------------totoal file size is %d\n",file_size);

	// 对于非原始文件，最后八个字节是标记字节，不必运算
	if(param->magic_number != ORIGNAL_FILE)
	{
		calc_count = file_size - sizeof(ENCRIPT_FLAG_S);
		printf("-------calc_count= %d\n",calc_count);
		// 已经进行过偶次加密运算的，使用第一个加密因子进行异或运算；进行过奇数次加密的，则使用第二个因子运算
		if(param->count % 2 == 0)
		{
			calc_factor = ENCRIPTION_FACTOR_ONE;
		}
		else
		{
			calc_factor = ENCRIPTION_FACTOR_TWO;
		}
	}
	else // 原始文件，即没有进行过加密的文件，使用第一个因子
	{
		calc_count = file_size;
		calc_factor = ENCRIPTION_FACTOR_ONE;
	}
	printf("-------------calc count=%d\n",calc_count);
	// 分配原始文件大小的字节空间
	read_file_buf = (char *)malloc(calc_count);
	// 定位到文件开头，进行读取
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
	// 将文件的每个字节进行异或运算
	for(i=0; i<calc_count; i++)
	{
		printf("read_buf[%d]=%d  \n", i , read_file_buf[i]);
		read_file_buf[i]^=calc_factor;
		printf("after calc read_buf[%d]=%d  \n", i , read_file_buf[i]);
	}

	//运算完后先关闭文件，然后以w+ 方式再次打开，这样才能重新将文件内容写入到原先位置，否则将是追加到末尾

	fclose(fd);

	fd = fopen(file_name, "w+");
	if(ret < 0)
	{
		printf("encode file open file failed\n");
		return -1;
	}


	int temp_size0 = ftell(fd);
	printf("~~~~~~~~~~~~~~ the encode file size is %d\n",temp_size0);



	// 定位到开头，将计算过的加密内容写入
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

	// 释放内存
	free(read_file_buf);

	//加密完一次后，将加密标记写入文件末尾
	flag.magic_number = ENCODE_FLAG;
	flag.count = param->count +1;
	memcpy(temp_flag, &flag, sizeof(ENCRIPT_FLAG_S));
	
	//定位到文件结尾，写入标记
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
*  函数功能: 对文件进行解密
   输入参数:  文件的加解密标记parm
			  文件名 file_name
   返回值:  成功返回0
		   失败返回-1
*/
int decode_file(ENCRIPT_FLAG_S* param, char * file_name)
{
	int ret;
	FILE* fd;
	int file_size;
	int original_file_size;
	bool flag_choose_factor = false;
	char *read_file_buf;
	//将要写入文件的加解密标记
	char temp_flag[8];
	ENCRIPT_FLAG_S flag;

	fd = fopen(file_name, "a+");
	if(fd <0)
	{
		printf("open the file failed, please input the right file name\n");
		return -1;
	}


	// 将文件所有的内容读出来放到一块内存中，假设文件不是非常大
	ret = fseek(fd, 0, SEEK_END);
	if(ret < 0)
	{
		printf("encode file seek failed\n");
		fclose(fd);
		return -1;
	}
	
	// 整个文件大小，包括加解密字节
	file_size = ftell(fd);
	original_file_size = file_size - sizeof(ENCRIPT_FLAG_S);


	printf("~~~~~~~~~~~~~~~~~~~~~decode original_file_size is %d\n",original_file_size);

	// 分配原始文件大小的字节空间
	read_file_buf = (char *)malloc(original_file_size);

	// 定位到文件开头，进行读取
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



	// 判断文件中的加密次数，选择先用哪个运算因子

	if(param->count % 2 == 0)
	{
		flag_choose_factor = false;
	}
	else
	{
		flag_choose_factor = true;
	}



	int m,k;
	// 循环轮回使用两个因子进行异或运算，只是要确定好先用哪一个
	for(m=0; m<param->count; m++)
	{
		if(flag_choose_factor) // 奇数次加密，先用第一个因子
		{
			// 将所有字节都进行异或运算一次
			for(k=0; k<original_file_size; k++)
			{
				read_file_buf[k]^= ENCRIPTION_FACTOR_ONE;
			}
			flag_choose_factor = false;
		}
		else  // 偶数次加密，用第二个因子
		{
			for(k=0; k<original_file_size; k++)
			{
				read_file_buf[k]^= ENCRIPTION_FACTOR_TWO;
			}
			flag_choose_factor = true;
		}
	}


		//运算完后先关闭文件，然后以w+ 方式再次打开，这样才能重新将文件内容写入到原先位置，否则将是追加到末尾

	fclose(fd);

	fd = fopen(file_name, "w+");
	if(ret < 0)
	{
		printf("encode file open file failed\n");
		return -1;
	}

	// 定位到开头，将计算过的加密内容写入
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

	// 释放内存
	free(read_file_buf);

	
	//解密完后，将加解密标记写入文件末尾
	flag.magic_number = DECODE_FLAG;
	flag.count = 0;
	memcpy(temp_flag, &flag, sizeof(ENCRIPT_FLAG_S));
	
	//定位到文件结尾，写入标记
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
	函数功能描述： 读取命令行输入操作
				   根据操作读取文件最后标记字节，进行加密或者解密
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


	
	// 判断参数输入个数是否正确
	if(argc != 3)
	{
		printf(" please input the right parm\n");
		return 0;
	}

	command = argv[1];
	printf("the argv is %s  command is %s\n",argv[1], command);
	file_name = argv[2];

	//判断操作命令是否正确
	encode_opt = (strcmp(command, "encode") == 0);
	decode_opt = (strcmp(command, "decode") == 0);

	if((!encode_opt) && (!decode_opt))
	{
		printf("your input command is wrong ,please input the rigth command\n");
		return 0;
	}
	
	// 操作命令输入正确，则可以进行文件读标记操作
	ret = read_file_flag(file_name, &file_flag);
	printf("1main---------magic=%#x\n", file_flag.magic_number);

	if(ret == 0)
	{

		// 对于原始没有进行处理的文件，读取到的数据是未知的，要将文件状态进行转换处理
		if((file_flag.magic_number != ENCODE_FLAG)&&(file_flag.magic_number != DECODE_FLAG))
		{
			file_flag.magic_number = ORIGNAL_FILE;
			file_flag.count = 0;
		}
		printf("2main---------magic=%#x\n", file_flag.magic_number);

		if(encode_opt)
		{
			// 根据文件状态提示是否需要加密

			// 判断文件的加密次数，已经加密进行提示，是否还要加密，是则继续加密，否则直接退出
			if(file_flag.magic_number == ENCODE_FLAG)
			{
				printf("the file is alread encoded,would you like to encode it again?\n");
				printf("if you think so ,please input y ,else please input n\n");
				// 捕捉用户输入的按键
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
			// 根据文件状态提示文件是否需要解密
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