#ifndef SURL_HPP
#define SURL_HPP

#define Download(a)		DownRequest((char*)a)
#define GET(a)			request((char*)a)
#define STR_ERR (-1)
#define HTTP 0
#define HTTPS 1

int reversestrf(const char* source, const char* find);
void initialise();
int strfind(const char* source, const char* find);
void httpsdown(const char* url, const char*path);
void httpdown(const char* url, const char*path);
char* https(const char* url, const char*path);
char* http(const char* url, const char*path);
char* path(const char* url);
void DownRequest(char*url);
char* request(char* url);

#endif