#include <sys/types.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <stdbool.h>

#include <hiredis.h>
#include <err.h>
#include <event.h>
#include <evhttp.h>

#define VERSION "1.3.1"


/* 全局设置 */
redisContext* redis_client = NULL;
char *httpsqs_settings_pidfile; /* PID文件 */

char *urldecode(char *input_str) 
{
		int len = strlen(input_str);
		char *str = strdup(input_str);
		
        char *dest = str; 
        char *data = str; 

        int value; 
        int c; 

        while (len--) { 
                if (*data == '+') { 
                        *dest = ' '; 
                } 
                else if (*data == '%' && len >= 2 && isxdigit((int) *(data + 1)) 
  && isxdigit((int) *(data + 2))) 
                { 

                        c = ((unsigned char *)(data+1))[0]; 
                        if (isupper(c)) 
                                c = tolower(c); 
                        value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16; 
                        c = ((unsigned char *)(data+1))[1]; 
                        if (isupper(c)) 
                                c = tolower(c); 
                                value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10; 

                        *dest = (char)value ; 
                        data += 2; 
                        len -= 2; 
                } else { 
                        *dest = *data; 
                } 
                data++; 
                dest++; 
        } 
        *dest = '\0'; 
        return str; 
}

static void show_help(void)
{
	char *b = "--------------------------------------------------------------------------------------------------\n"
		  "HTTP Simple Redis Queue Service - httpsqs v" VERSION " (March 16, 2011)\n\n"
		  "This is free software, and you are welcome to modify and redistribute it under the New BSD License\n"
		  "\n"
		   "-l <ip_addr>  interface to listen on, default is 0.0.0.0\n"
		   "-p <num>      TCP port number to listen on (default: 2789)\n"
		   "-r <redis_ip_addr>  addr redis server is listening on, default is 127.0.0.1\n"
		   "-o <redis_num>      port number redis server is listening on (default: 6379)\n"
		   "-i <file>     save PID in <file> (default: /tmp/httpsqs.pid)\n"
		   "-t <second>   timeout for an http request (default: 3)\n"
		   "-d            run as a daemon\n"
		   "-h            print this help and exit\n\n"
		   "Use command \"killall httpsqs\", \"pkill httpsqs\" and \"kill `cat /tmp/httpsqs.pid`\" to stop httpsqs.\n"
		   "Please note that don't use the command \"pkill -9 httpsqs\" and \"kill -9 PID of httpsqs\"!\n"
		   "\n"
		   "--------------------------------------------------------------------------------------------------\n"
		   "\n";
	fprintf(stderr, b, strlen(b));
}

/* 查看单条队列内容 */
char *httpsqs_view(const char* httpsqs_input_name)
{
    return "#TODO";
	//return queue_value;
}

/* 处理模块 */
void httpsqs_handler(struct evhttp_request *req, void *arg)
{
        struct evbuffer *buf;
        buf = evbuffer_new();
		
		/* 分析URL参数 */
		char *decode_uri = strdup((char*) evhttp_request_uri(req));
		struct evkeyvalq httpsqs_http_query;
		evhttp_parse_query(decode_uri, &httpsqs_http_query);
		free(decode_uri);
		
		/* 接收GET表单参数 */
		const char *httpsqs_input_name = evhttp_find_header (&httpsqs_http_query, "name"); /* 队列名称 */
		const char *httpsqs_input_charset = evhttp_find_header (&httpsqs_http_query, "charset"); /* 操作类别 */
		const char *httpsqs_input_opt = evhttp_find_header (&httpsqs_http_query, "opt"); /* 操作类别 */
		const char *httpsqs_input_data = evhttp_find_header (&httpsqs_http_query, "data"); /* 操作类别 */
		
		/* 返回给用户的Header头信息 */
		if (httpsqs_input_charset != NULL && strlen(httpsqs_input_charset) <= 40) {
			char *content_type = (char *)malloc(64);
			memset(content_type, '\0', 64);
			sprintf(content_type, "text/plain; charset=%s", httpsqs_input_charset);
			evhttp_add_header(req->output_headers, "Content-Type", content_type);
			free(content_type);
		} else {
			evhttp_add_header(req->output_headers, "Content-Type", "text/plain");
		}
		evhttp_add_header(req->output_headers, "Connection", "keep-alive");
		evhttp_add_header(req->output_headers, "Cache-Control", "no-cache");
		
		/*参数是否存在判断 */
		if (httpsqs_input_name != NULL && httpsqs_input_opt != NULL && strlen(httpsqs_input_name) <= 256) {
			/* 入队列 */
			if (strcmp(httpsqs_input_opt, "put") == 0) {
				/* 优先接收POST正文信息 */
				int buffer_data_len;
				buffer_data_len = EVBUFFER_LENGTH(req->input_buffer);
                char* httpsqs_input_postbuffer = NULL;
                char* buffer_data = NULL;
                if (buffer_data_len <=0 && httpsqs_input_data == NULL) {
					evbuffer_add_printf(buf, "%s", "HTTPSQS_PUT_ERROR");
                } else {
                    if (buffer_data_len > 0) {
                        buffer_data = (char *)malloc(buffer_data_len + 1);
                        memset(buffer_data, '\0', buffer_data_len + 1);
                        memcpy (buffer_data, EVBUFFER_DATA(req->input_buffer), buffer_data_len);
                        httpsqs_input_postbuffer = urldecode(buffer_data);

                    /* 如果POST正文无内容，则取URL中data参数的值 */
                    } else if (httpsqs_input_data != NULL) {
                        buffer_data_len = strlen(httpsqs_input_data);
                        buffer_data = (char *)malloc(buffer_data_len + 1);
                        memset(buffer_data, '\0', buffer_data_len + 1);
                        memcpy (buffer_data, httpsqs_input_data, buffer_data_len);
                        httpsqs_input_postbuffer = urldecode(buffer_data);
                    } 

                    redisReply* reply = (redisReply*)redisCommand(redis_client, "RPUSH %s %s", httpsqs_input_name, httpsqs_input_postbuffer); 
                    if (reply == NULL) {
                        fprintf(stderr, "Put queue message failed:%s [error]:%d", httpsqs_input_name, reply->type);
                        evbuffer_add_printf(buf, "%s", "HTTPSQS_PUT_ERROR");
                    }
                    else {
                        evbuffer_add_printf(buf, "%s", "HTTPSQS_PUT_OK");
                        freeReplyObject(reply);
                    }
                    if (httpsqs_input_postbuffer != NULL) free(httpsqs_input_postbuffer);
                    if (buffer_data != NULL) free(buffer_data);
                }
            }
			else if (strcmp(httpsqs_input_opt, "get") == 0) {
                /* 出队列 */
                redisReply* reply = (redisReply*)redisCommand(redis_client, "LPOP %s", httpsqs_input_name);
                if (reply == NULL) {
					evbuffer_add_printf(buf, "%s", "HTTPSQS_GET_ERROR");
				} else if (reply->type == REDIS_REPLY_NIL){
					evbuffer_add_printf(buf, "%s", "HTTPSQS_GET_END");
                    freeReplyObject(reply);
                } else {
                    evbuffer_add_printf(buf, "%s", reply->str);
                    freeReplyObject(reply);
                }
			}
			else if (strcmp(httpsqs_input_opt, "status") == 0) {
                /* 查看队列状态（普通浏览方式） */
                evbuffer_add_printf(buf, "#TODO");
			}
			else if (strcmp(httpsqs_input_opt, "status_json") == 0) {
                /* 查看队列状态（JSON方式，方便客服端程序处理） */
                evbuffer_add_printf(buf, "#TODO");
			}			
			else if (strcmp(httpsqs_input_opt, "view") == 0 ) {
                /* 查看单条队列内容 */
                evbuffer_add_printf(buf, "#TODO");
			} else {
				/* 命令错误 */
				evbuffer_add_printf(buf, "%s", "HTTPSQS_ERROR");				
			}
		} else {
			/* 命令错误 */
			evbuffer_add_printf(buf, "%s", "HTTPSQS_ERROR");
		}
		
		/* 输出内容给客户端 */
        evhttp_send_reply(req, HTTP_OK, "OK", buf);
		
		/* 内存释放 */
		evhttp_clear_headers(&httpsqs_http_query);
		evbuffer_free(buf);
}

/* 信号处理 */
static void kill_signal(const int sig) {
	remove(httpsqs_settings_pidfile);
    redisFree(redis_client);
    exit(0);
}


int main(int argc, char **argv)
{
	int c;
	/* 默认参数设置 */
	char *httpsqs_settings_listen = "0.0.0.0";
	int httpsqs_settings_port = 2789;
    char *redis_settings_listen = "127.0.0.1";
    int redis_settings_port = 6379;
	bool httpsqs_settings_daemon = false;
	int httpsqs_settings_timeout = 3; /* 单位：秒 */
	httpsqs_settings_pidfile = "/tmp/httpredisq.pid";

    /* process arguments */
    while ((c = getopt(argc, argv, "l:p:r:o:i:t:dh")) != -1) {
        switch (c) {
        case 'l':
            httpsqs_settings_listen = strdup(optarg);
            break;
        case 'p':
            httpsqs_settings_port = atoi(optarg);
            break;
        case 'r':
            redis_settings_listen = strdup(optarg);
            break;
        case 'o':
            redis_settings_port = atoi(optarg);
            break;
        case 'i':
            httpsqs_settings_pidfile = strdup(optarg);
            break;			
        case 't':
            httpsqs_settings_timeout = atoi(optarg);
            break;
        case 'd':
            httpsqs_settings_daemon = true;
            break;
		case 'h':
        default:
            show_help();
            return 1;
        }
    }

    redis_client = redisConnect(redis_settings_listen, redis_settings_port);
    if (redis_client -> err) {
        fprintf(stderr, "Connect redis server error:%s\n", redis_client->errstr);
        return 1;
    }
    
	/* 如果加了-d参数，以守护进程运行 */
	if (httpsqs_settings_daemon == true){
        pid_t pid;

        /* Fork off the parent process */       
        pid = fork();
        if (pid < 0) {
                exit(EXIT_FAILURE);
        }
        /* If we got a good PID, then
           we can exit the parent process. */
        if (pid > 0) {
                exit(EXIT_SUCCESS);
        }
	}
	
	/* 将进程号写入PID文件 */
	FILE *fp_pidfile;
	fp_pidfile = fopen(httpsqs_settings_pidfile, "w");
	fprintf(fp_pidfile, "%d\n", getpid());
	fclose(fp_pidfile);
	
	/* 忽略Broken Pipe信号 */
	signal(SIGPIPE, SIG_IGN);
	
	/* 处理kill信号 */
	signal (SIGINT, kill_signal);
	signal (SIGKILL, kill_signal);
	signal (SIGQUIT, kill_signal);
	signal (SIGTERM, kill_signal);
	signal (SIGHUP, kill_signal);
	
	/* 请求处理部分 */
    struct evhttp *httpd;

    event_init();
    httpd = evhttp_start(httpsqs_settings_listen, httpsqs_settings_port);
	if (httpd == NULL) {
		fprintf(stderr, "Error: Unable to listen on %s:%d\n\n", httpsqs_settings_listen, httpsqs_settings_port);		
		exit(1);		
	}
	evhttp_set_timeout(httpd, httpsqs_settings_timeout);

    /* Set a callback for requests to "/specific". */
    /* evhttp_set_cb(httpd, "/select", select_handler, NULL); */

    /* Set a callback for all other requests. */
    evhttp_set_gencb(httpd, httpsqs_handler, NULL);

    event_dispatch();

    /* Not reached in this code as it is now. */
    evhttp_free(httpd);

    return 0;
}
