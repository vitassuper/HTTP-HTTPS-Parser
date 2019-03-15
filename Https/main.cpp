#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "requests.hpp"
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <string>
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#pragma comment (lib, "lib/libcryptoMDd.lib")
#pragma comment (lib, "lib/libsslMDd.lib")
#pragma comment (lib, "lib/32/WS2_32.lib")




int reversestrf(const char* source, const char* find) {
	int len = strlen(source);
	int findlen = strlen(find);
	for (int i = len; i > 0; i--) {
		if (source[i] == find[0]) {
			for (int k = i, d = 0; (d <= findlen && k <= len); k++, d++) {
				if (d == findlen) return i;
				if (source[k] != find[d]) break;
			}
		}
	}
	return -1;
}

void initialiseWS() {
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NULL) std::cout << "Error";
}

int strfind(const char* source, const char* find) {
	int len = strlen(source);
	int findlen = strlen(find);
	for (int i = 0; i < len; i++) {
		if (source[i] == find[0]) {
			for (int k = i, d = 0; (d <= findlen && k <= len); k++, d++) {
				if (d == findlen) return i;
				if (source[k] != find[d]) break;
			}
		}
	}
	return -1;
}

void httpsdown(const char* url, const char*path) {
	char link[100];
	char request[2056];
	strcpy(link, url);
	strcat(link, ":443");
	BIO* bio;
	SSL* ssl;
	SSL_CTX* ctx;
	FILE* file = nullptr;

	SSL_library_init();

	//
	//	Adds all algorithms to the table (digests and ciphers)
	//
	OpenSSL_add_all_algorithms();

	//
	//	Creates a new SSL_CTX object as framework to establish TLS/SSL
	//	or DTLS enabled connections
	//
	ctx = SSL_CTX_new(SSLv23_client_method());

	//
	//	-> Error check
	//
	if (ctx == NULL)
	{
		printf("Ctx is null\n");
	}

	//
	//	 Specifies the locations for ctx, at which CA certificates
	//	 for verification purposes are located.
	//
	if (!SSL_CTX_load_verify_locations(ctx, "api.pem", NULL))
	{
		printf("Faild load verify locations\n");
	}

	//
	//	 Creates a new BIO chain consisting of an SSL BIO
	//
	bio = BIO_new_ssl_connect(ctx);


	BIO_set_conn_hostname(bio, link);


	BIO_get_ssl(bio, &ssl);
	if (!(ssl != NULL)) {
		printf("Error\n");
	}

	if (SSL_set_tlsext_host_name(ssl, url) != 1)
		printf("Error\n");


	if (BIO_do_connect(bio) != 1) {
		printf("Failed connection\n");
		char *errr = new char[256];
		ERR_error_string(ERR_get_error(), errr);
		printf("%s\n", errr);
		ERR_print_errors(bio);
		exit(EXIT_FAILURE);
	}
	else {
		printf("Connected\n");
	}

	if (BIO_do_handshake(bio) != 1)
		printf("Error");
	//
	//	Retrieves the SSL pointer of BIO, it can then be manipulated
	//	using the standard SSL library functions
	//



	//
	//	adds the mode set via bitmask in mode to ssl.
	//	Options already set before are not overwritten.
	//
	//		SSL_MODE_AUTO_RETRY: Never bother the application with retries
	//							 if the transport is blocking.  ssl_read(3) or
	//							 ssl_write(3) would return with -1
	//
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	X509* cert = SSL_get_peer_certificate(ssl);
	if (cert) { X509_free(cert); } /* Free immediately */
	if (NULL == cert) printf("Error\n");

	//
	//	Returns the result of the verification of the X509 certificate
	//	presented by the peer, if any.
	//
	if (SSL_get_verify_result(ssl) != X509_V_OK)
	{
		printf("Failed get verify result\n");
		printf("Certificate verification error: %li\n",
			SSL_get_verify_result(ssl));
	}


	strcpy(request, "GET ");
	if (path == NULL) {
		strcat(request, "/");
	}
	else strcat(request, path);
	strcat(request, " HTTP/1.1\r\nHost: ");
	strcat(request, url);
	strcat(request, "\r\nAccept: */*\r\nConnection: close\r\n\r\n");
	printf("%s", request);
	if (BIO_write(bio, request, sizeof(request)) <= 0)
	{
		//
		//	Handle failed write here
		//
		if (!BIO_should_retry(bio))
		{
			// Not worth implementing, but worth knowing.
		}

		printf("Failed write\n");
	}

	bool flag = 1;
	int size;
	char buf[1024];
	int j = 0;
	do {
		size = BIO_read(bio, buf, 1024);
		if (flag) {
			int k = strfind(buf, "301 Moved Permanently");
			if (k != STR_ERR) {
				char wlink[100];
				strcpy(wlink, "www.");
				strcat(wlink, url);
				return httpsdown(wlink, path);
			}
			char name[300];
			j = strfind(buf, "\r\n\r\n") + 4;
			int i = reversestrf(path, "/") + 1;
			int t = 0;
			while (path[i] != '\0') {
				name[t] = path[i];
				i++, t++;
			}
			name[t] = '\0';
			flag = 0;
			file = fopen(name, "wb");
		}
		if (size>0) {
			for (int i = j; i < size; i++) {
				fputc(buf[i], file);
			}
		}
		j = 0;
	} while (size > 0 || BIO_should_retry(bio));
	printf("Done reading\n");
}

void httpdown(const char* url, const char*path) {
	FILE* file = nullptr;
	initialiseWS();
	SOCKET	req;
	char buf[1024];
	hostent*hn;
	char request[2056];
	sockaddr_in	adr;
	if (INVALID_SOCKET == (req = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))) std::cout << "Error 1";
	if (NULL == (hn = gethostbyname(url))) std::cout << "Error 2";
	adr.sin_family = AF_INET;
	adr.sin_addr.S_un.S_addr = *(DWORD*)hn->h_addr_list[0];
	adr.sin_port = htons(80);
	strcpy(request, "GET ");
	if (path == NULL) {
		strcat(request, "/");
	}
	else strcat(request, path);
	strcat(request, " HTTP/1.1\r\nHost: ");
	strcat(request, url);
	strcat(request, "\r\nAccept: */*\r\nConnection: close\r\n\r\n");
	printf("%s", request);
	if (SOCKET_ERROR == connect(req, (sockaddr*)&adr, sizeof(adr))) std::cout << "Error 3\n";
	if (SOCKET_ERROR == send(req, request, sizeof(request), 0)) std::cout << "Error 4\n";
	bool flag = 1;
	int j;
	int len;
	do {
		if (SOCKET_ERROR == (len = recv(req, (char *)&buf, sizeof(buf), 0))) { std::cout << "Error 5\n"; break; }
		if (flag) {
			if (strfind(buf, "HTTP/1.1 301") != STR_ERR) {
				int i = strfind(buf, "Location");
				if (i != STR_ERR) {
					if (strfind(buf, "https://") != STR_ERR) {
						return httpsdown(url, path);
					}
					else {
						char wlink[100];
						strcpy(wlink, "www.");
						strcat(wlink, url);
						system("cls");
						return httpdown(wlink, path);
					}
				}
			}
			char name[300];
			j = strfind(buf, "\r\n\r\n") + 4;
			int i = reversestrf(path, "/") + 1;
			int t = 0;
			while (path[i] != '\0') {
				name[t] = path[i];
				i++, t++;
			}
			name[t] = '\0';
			flag = 0;
			file = fopen(name, "wb");

		}
		for (int i = j; i < len; i++) {
			fputc(buf[i], file);
		}
		j = 0;
	} while (len != 0);
	if (SOCKET_ERROR == closesocket(req)) std::cout << "Error 6\n";
}

char* https(const char* url, const char*path) {
		char link[100];
		char request[2056];
		strcpy(link, url);
		strcat(link, ":443");
		BIO* bio;
		SSL* ssl;
		SSL_CTX* ctx;

		SSL_library_init();

		//
		//	Adds all algorithms to the table (digests and ciphers)
		//
		OpenSSL_add_all_algorithms();

		//
		//	Creates a new SSL_CTX object as framework to establish TLS/SSL
		//	or DTLS enabled connections
		//
		ctx = SSL_CTX_new(SSLv23_client_method());

		//
		//	-> Error check
		//
		if (ctx == NULL)
		{
			printf("Ctx is null\n");
		}

		//
		//	 Specifies the locations for ctx, at which CA certificates
		//	 for verification purposes are located.
		//
		if (!SSL_CTX_load_verify_locations(ctx, "olx.pem", NULL))
		{
			printf("Faild load verify locations\n");
		}

		//
		//	 Creates a new BIO chain consisting of an SSL BIO
		//
		bio = BIO_new_ssl_connect(ctx);

		
		BIO_set_conn_hostname(bio, link);


		BIO_get_ssl(bio, &ssl);
		if (!(ssl != NULL)) {
			printf("Error\n");
		}
		
		if(SSL_set_tlsext_host_name(ssl, url)!=1)
			printf("Error\n");


		if (BIO_do_connect(bio)!=1){
			printf("Failed connection\n");
			char *errr=new char[256];
			ERR_error_string(ERR_get_error(), errr);
			printf("%s\n", errr);
			ERR_print_errors(bio);
			exit(EXIT_FAILURE);
		}
		else{
			printf("Connected\n");
		}


		//
		//	Retrieves the SSL pointer of BIO, it can then be manipulated
		//	using the standard SSL library functions
		//



		//
		//	adds the mode set via bitmask in mode to ssl.
		//	Options already set before are not overwritten.
		//
		//		SSL_MODE_AUTO_RETRY: Never bother the application with retries
		//							 if the transport is blocking.  ssl_read(3) or
		//							 ssl_write(3) would return with -1
		//
		SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

		X509* cert = SSL_get_peer_certificate(ssl);
		if (cert) { X509_free(cert); } /* Free immediately */
		if (NULL == cert) printf("Error\n");

		//
		//	Returns the result of the verification of the X509 certificate
		//	presented by the peer, if any.
		//
		if (SSL_get_verify_result(ssl) != X509_V_OK)
		{
			printf("Failed get verify result\n");
			printf("Certificate verification error: %li\n",
				SSL_get_verify_result(ssl));
		}

		
		strcpy(request, "GET ");
		if (path == NULL) {
			strcat(request, "/");
		}
		else strcat(request, path);
		strcat(request, " HTTP/1.1\r\nHost: ");
		strcat(request, url);
		strcat(request, "\r\nConnection: close\r\n\r\n");
		
		if (BIO_write(bio, request, sizeof(request)) <= 0)
		{
			//
			//	Handle failed write here
			//
			if (!BIO_should_retry(bio))
			{
				// Not worth implementing, but worth knowing.
			}

			printf("Failed write\n");
		}


		int size;
		int t = 0;
		int count = 0;
		char buf[1024];
		char *bbuf;
		bbuf = (char*)malloc(1);
		do{
			size = BIO_read(bio, buf, 1024); 
			if(size>0){
			count += size;
			bbuf = (char*)realloc(bbuf,count);
			for (int i = 0; i < size; i++) {
				bbuf[t] = buf[i];
				t++;
			}
			}
		} while (size > 0 || BIO_should_retry(bio));
		printf("Done reading\n");
		int i = strfind(buf, "301 Moved Permanently");
		if(i!=STR_ERR){
			char wlink[100];
			strcpy(wlink, "www.");
			strcat(wlink, url);
			return https(wlink, path);
		}
		BIO_free_all(bio);
		SSL_CTX_free(ctx);
		bbuf[t] ='\0';
		return bbuf;
}

char* http(const char* url, const char*path) {
	FILE* file = nullptr;
	WSADATA wsaData;
	if(WSAStartup(MAKEWORD(2, 2), &wsaData)!=NULL) std::cout<<"Error";
	SOCKET	req;
	char buf[1024];
	hostent*hn;
	char request[2056];
	sockaddr_in	adr;
	if (INVALID_SOCKET == (req = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))) std::cout << "Error 1";
	if (NULL == (hn = gethostbyname(url))) std::cout << "Error 2";
	adr.sin_family = AF_INET;
	adr.sin_addr.S_un.S_addr = *(DWORD*)hn->h_addr_list[0];
	adr.sin_port = htons(80);
	strcpy(request,"GET ");
	if (path == NULL) {
		strcat(request, "/");
	}
	else strcat(request, path);
	strcat(request, " HTTP/1.1\r\nHost: ");
	strcat(request, url);
	strcat(request, "\r\nConnection: close\r\n\r\n");
	if (SOCKET_ERROR == connect(req, (sockaddr*)&adr, sizeof(adr))) std::cout << "Error 3\n";
	if (SOCKET_ERROR == send(req, request, sizeof(request), 0)) std::cout << "Error 4\n";
	int len;
	int t = 0;
	int count = 0;
	char *bbuf;
	bbuf = (char*)malloc(1);
	do {
		if (SOCKET_ERROR == (len = recv(req, (char *)&buf, sizeof(buf), 0))) { std::cout << "Error 5\n"; break; }
		count += len;
		bbuf = (char*)realloc(bbuf, count);
		for (int i = 0; i < len; i++) {
			fputc(buf[i], file);
			bbuf[t] = buf[i];
			t++;
		}
	} while (len != 0);
	if (strfind(buf, "HTTP/1.1 301") != STR_ERR) {
		int i = strfind(buf, "Location");
			if(i!= STR_ERR){
				if (strfind(buf, "https://")!=STR_ERR) {
					return https(url, path);
				}	
				else{
						char wlink[100];
						strcpy(wlink, "www.");
						strcat(wlink, url);
						system("cls");
						return http(wlink, path);
					}
			}
		}
	if (SOCKET_ERROR == closesocket(req)) std::cout << "Error 6\n";
	bbuf[t] = '\0';
	return bbuf;
}

char* path(const char* url) {
	char*domain = (char*)url;
	char *temp = (char*)malloc(2056);
	char *ach = (char*)strchr(domain, '/');
	if (ach != NULL) {
		int t = 0;
		int i = ach - domain;
		for (i; i < strlen(domain); i++) {
			temp[t] = domain[i];
			t++;
		}
		domain = { 0 };
		temp[t] = '\0';
		t = 0;
		domain = temp;
	}
	return domain;
}

void DownRequest(char*url) {
	bool type = HTTP;
	char*domain = (char*)malloc(2056);
	domain = (char*)url;
	char*tpath;
	int len = strlen(domain);
	char *temp = (char*)malloc(2056);
	if (int i = strfind(domain, "http://") != -1) {
		i += 6;
		int t = 0;
		for (i; i < len; i++) {
			temp[t] = domain[i];
			t++;
		}
		domain = { 0 };
		t = 0;
		temp[i - 7] = (char)'\0';
		domain = temp;
		i = strfind(domain, "www.");
		if (i != -1) {
			i += 4;
			for (i; i < len; i++) {
				temp[t] = domain[i];
				t++;
			}
			domain = { 0 };
			domain = temp;
		}
		type = HTTP;
	}
	if (int i = strfind(domain, "https://") != -1) {
		i += 7;
		int t = 0;
		for (i; i < len; i++) {
			temp[t] = domain[i];
			t++;
		}
		domain = { 0 };
		t = 0;
		temp[i - 8] = (char)'\0';
		domain = temp;
		i = strfind(domain, "www.");
		if (i != -1) {
			i += 4;
			for (i; i < len; i++) {
				temp[t] = domain[i];
				t++;
			}
			domain = { 0 };
			domain = temp;
		}
		type = HTTPS;
	}
	if (int i = strfind(domain, "www.") != -1) {
		i += 3;
		int t = 0;
		for (i; i < len; i++) {
			temp[t] = domain[i];
			t++;
		}
		domain = { 0 };
		t = 0;
		temp[i - 4] = (char)'\0';
		domain = temp;
		type = HTTP;
	}
	else if (type != HTTPS) type = HTTP;
	tpath = path(domain);
	char *ach = (char*)strchr(domain, '/');
	if (ach != NULL) {
		int t = 0;
		int k = ach - domain;
		int i = 0;
		for (i; i < k; i++) {
			temp[t] = domain[i];
			t++;
		}
		domain = { 0 };
		t = 0;
		temp[i] = (char)'\0';
		domain = temp;
	}
	else tpath = 0;
	if (type == HTTP) {
		return httpdown(domain, tpath);
	}
	else return httpsdown(domain, tpath);
}

char* request(char* url) {
	bool type=HTTP;
	char*domain = (char*)malloc(2056);
	domain = (char*)url;
	char*tpath;
	int len = strlen(domain);
	char *temp = (char*)malloc(2056);
	if (int i=strfind(domain, "http://")!=STR_ERR) {
		i += 6;
		int t = 0;
		for (i; i < len; i++) {
			temp[t] = domain[i];
			t++;
		}
			domain = { 0 };
			t = 0;
			temp[i-7] = (char)'\0';
			domain = temp;
			i = strfind(domain, "www.");
			if (i != -1) {
				i += 4;
				for (i; i < len; i++) {
					temp[t] = domain[i];
					t++;
				}
				domain = { 0 };
				domain = temp;
			}
			type = HTTP;
	}
		if (int i = strfind(domain, "https://") != STR_ERR) {
			i += 7;
			int t = 0;
			for (i; i < len; i++) {
				temp[t] = domain[i];
				t++;
			}
			domain = { 0 };
			t = 0;
			temp[i-8] = (char)'\0';
			domain = temp;
			i = strfind(domain, "www.");
			if(i!=-1){
				i += 4;
				for (i; i < len; i++) {
					temp[t] = domain[i];
					t++;
				}
				domain = { 0 };
				domain = temp;
			}
			type = HTTPS;
		}
		if (int i = strfind(domain, "www.") != STR_ERR) {
			i += 3;
			int t = 0;
			for (i; i < len; i++){
				temp[t] = domain[i];
			t++;
		}
		domain = { 0 };
		t = 0;
		temp[i-4] = (char)'\0';
		domain = temp;
		type = HTTP;
		}
		else if(type!=HTTPS) type = HTTP;
		tpath=path(domain);
		char *ach = (char*)strchr(domain, '/');
		if (ach != NULL) {
			int t = 0;
			int k = ach - domain;
			int i = 0;
			for (i; i < k; i++) {
				temp[t] = domain[i];
				t++;
			}
			domain = { 0 };
			t = 0;
			temp[i] = (char)'\0';
			domain = temp;
		}
		else tpath = 0;
		if (type == HTTP) {
			return http(domain, tpath);
		}
		else return https(domain, tpath);
}

int main(void){
	std::string str;
	str=GET("https://www.dropbox.com/s/7fjcmy23uds16ja/Laboratory%20Work%206.docx");
	std::cout << str;
	//download("upload.wikimedia.org", "/wikipedia/commons/thumb/a/ae/GO_Logo.svg/1200px-GO_Logo.svg.png");
	//httpdown("htmlbook.ru","/themes/hb/img/logo.png");
	//Download("www.openssl.org/source/openssl-fips-ecp-2.0.16.tar.gz");
	system("pause");
	return 0;
}