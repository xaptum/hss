int hss_proxy_open_socket(int local_id, void *context);
int hss_proxy_connect_socket(int local_id, struct sockaddr *addr, int alen, void *context);
void hss_proxy_close_socket(int local_id, void *context);
int hss_proxy_write_socket(int sock_id, void *msg, int len, void *context);