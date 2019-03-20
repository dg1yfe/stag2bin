
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <strings.h>

struct S_STAG_HDR{
	uint8_t magic_number;
	uint32_t size_be;
	uint32_t address_be;
};


uint32_t betole32(uint32_t be_data){
	uint32_t le_data;

	le_data  = be_data >> 24;
	le_data |= (be_data >> 8)  & 0xFF00;
	le_data |= (be_data << 8)  & 0xFF0000;
	le_data |= (be_data << 24) & 0xFF000000;

	return le_data;
}


int main(int argc, char **argv){
	int fd_in;
	int fd_out;
	uint8_t c;
	ssize_t len;
	uint32_t size, bytes_processed;
	uint32_t address;
	size_t ipos,opos;
	uint8_t checksum;
	int did_final_check;

	if((argc < 2) || (argc > 3) || (strcmp(argv[2],"--help")==0)){
		printf("Usage: stag2bin <stag file> <binfile>");
		printf("Usage: stag2bin <stag file>");
	}

	if(argc == 3){
		fd_out = open(argv[2], O_WRONLY);

		if(fd_out == -1){
			dprintf(STDERR_FILENO,"Error opening output file: %s\n", strerror(errno) );
			exit(1);
		}
	}
	else{
		fd_out = -1;
	}

	fd_in = open(argv[1], O_RDONLY);

	if(fd_in == -1){
		dprintf(STDERR_FILENO, "Error opening input file: %s\n", strerror(errno) );
		exit(1);
	}

	do{
		do{
			len = read(fd_in,&c,1);
			if( len == 0){
				dprintf(STDERR_FILENO,"Could not find header.\n");
				exit(1);
			}
			else if(len == -1){
				dprintf(STDERR_FILENO,"Error while reading from input file: %s.\n", strerror(errno));
				exit(1);
			}
		}while(c != 0x01);

		if(read(fd_in,&size, 4)<4){
			dprintf(STDERR_FILENO,"Unexpected end of file while reading size info.\n");
			exit(1);
		}

		size = betole32(size);
		printf("Size: %u\n", size);

		if(read(fd_in,&address, 4)<4){
			dprintf(STDERR_FILENO,"Unexpected end of file while reading address info.\n");
			exit(1);
		}

		if(size == 0){
			printf("End Of File marker found.\n");
			if(address == 0x53544147){
				printf("Address also is 'STAG'\n");
			}
			break;
		}

		address = betole32(address);
		printf("Address: %u\n", address);

		if(fd_out >= 0){
			opos = lseek(fd_out, (off_t) address, SEEK_SET);
		}

		ipos = bytes_processed = did_final_check = 0;
		checksum = 0;
		do{
			len = read(fd_in,&c,1);
			if(len < 0){
				dprintf(STDERR_FILENO,"Error while reading from input file at offset %zu.\n", ipos);
				exit(1);
			}
			if(len == 0){
				dprintf(STDERR_FILENO,"Unexpected end of file while data at offset %zu.\n",ipos);
				break;
			}
			ipos++;
			checksum += c;

			// after 1024 byte follows an intermediate checksum (1 Byte)
			if(((ipos % 1025) == 0) || (bytes_processed == size)){
				if(checksum != c){
					dprintf(STDERR_FILENO,"Checksum error at file offset / address: %8zu / %8x\n",ipos,address+bytes_processed-1);
				}
				checksum = 0;
				if(bytes_processed == size){
					did_final_check = 1;
				}
			}
			else{
				if(fd_out >= 0){
					// write data without intermediate checksum
					len = write(fd_out, &c, 11);
					if(len < 1){
						dprintf(STDERR_FILENO,"Error while writing to output file at offset / address %zu / %8x.\n", opos,address+bytes_processed-1);
						exit(1);
					}
					opos++;
				}
				bytes_processed++;
			}
		}while((bytes_processed < size) && (did_final_check==0));
	}while(1);

	return EXIT_SUCCESS;
}
