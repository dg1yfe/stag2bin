
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <strings.h>

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
	off_t garbage_bytes;
	uint8_t checksum;
	int did_final_check;
	int packet_count = 1;

	if((argc < 2) || (argc > 3) || ((argc == 2) && (strcmp(argv[1],"--help"))==0)){
		printf("Usage: stag2bin <stag file> <binfile>\n");
		printf("       stag2bin <stag file>\n");
		exit(0);
	}

	if(argc == 3){
		fd_out = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

		if(fd_out == -1){
			dprintf(STDERR_FILENO,"Error opening output file '%s'.\n%s\n",argv[2], strerror(errno) );
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

	ipos = 0;
	for(;;){
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

		if((ipos == 0) && (garbage_bytes = lseek(fd_in,0,SEEK_CUR)) != 1){
			printf("Skipped %zu Bytes of ASCII garbage before the header.\n",(size_t) garbage_bytes);
		}

		if(read(fd_in,&size, 4)<4){
			dprintf(STDERR_FILENO,"Unexpected end of file while reading size info.\n");
			exit(1);
		}

		printf("Packet No: %u\n",packet_count++);
		checksum = (size >> 24) + (size >> 16) + (size >> 8) + size;
		size = betole32(size);
		printf("Size: %u\n", size);

		if(read(fd_in,&address, 4)<4){
			dprintf(STDERR_FILENO,"Unexpected end of file while reading address info.\n");
			exit(1);
		}
		address = betole32(address);
		checksum += (address >> 24) + (address >> 16) + (address >> 8) + address;
		printf("Address: 0x%x\n", address);

		if(size == 0){
			printf("End Of File marker found.\n");
			if(address != 0x53544147){
				dprintf(STDERR_FILENO,"Adress is not 'STAG' (0x53 0x54 0x41 0x47) in EOF marker.\n");
			}
			c=checksum;
			if(read(fd_in,&c,1) < 1){
				dprintf(STDERR_FILENO,"Error while reading EOF markers checksum.\n");
			}
			else if((uint8_t)-checksum != c){
				dprintf(STDERR_FILENO,"Checksum error in EOF marker (expected: %02x, read: %02x).\n",(uint8_t)-checksum,c);
			}
			break;
		}

		if(fd_out >= 0){
			opos = lseek(fd_out, (off_t) address, SEEK_SET);
		}

		ipos = bytes_processed = did_final_check = 0;
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

			// after 1024 byte follows an intermediate checksum (1 Byte)
			if(((ipos % 1025) == 0) || (bytes_processed == size)){
				int8_t negcs;
				negcs = -((int8_t) checksum);
				if( (uint8_t) negcs != (uint8_t) c){
					dprintf(STDERR_FILENO,"Checksum error at file offset / address: %8zu / %8x\n",ipos,address+bytes_processed-1);
					dprintf(STDERR_FILENO,"Expected: 0x%02x, read: 0x%02x\n", (uint8_t) negcs, (uint8_t) c);
				}
				if(bytes_processed == size){
					did_final_check = 1;
				}
			}
			else{
				checksum += c;
				if(fd_out >= 0){
					// write data without intermediate checksum
					len = write(fd_out, &c, 1);
					if(len < 1){
						dprintf(STDERR_FILENO,"Error while writing to output file at offset / address %zu / %8x.\n", opos,address+bytes_processed-1);
						exit(1);
					}
					opos++;
				}
				bytes_processed++;
			}
		}while((bytes_processed < size) && (did_final_check==0));
	}

	if(fd_out >= 0)
		close(fd_out);

	close(fd_in);

	return EXIT_SUCCESS;
}
