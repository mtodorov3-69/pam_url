# pam_url - GPLv2, Sascha Thomas Spreitzer, https://fedorahosted.org/pam_url
# GPLv2 - Mirsad Goran Todorovac, 2022-02-03, do not overwrite the existing config file

libs		+= libcurl libconfig openssl

DESTDIR		= /usr/local

CFLAGS		+= -Wall -fPIC -pthread -D_GNU_SOURCE $(shell pkg-config --cflags ${libs})

LDFLAGS		+= -shared -lpam -pthread $(shell pkg-config --libs ${libs})

arch		:= $(shell uname -m)
pamlib		:= lib/security

obj			:= pam_url.so
# objc		:= ${shell ls pam_url*.c}
objc		:= ${shell ls *.c}
objo		:= ${objc:%.c=%.o}

# If platform is AMD/Intel 64bit
ifeq (${arch},x86_64)
pamlib := lib64/security
endif
ifeq (${arch},ppc64)
pamlib := lib64/security
endif

PAM_URL=/usr/local/etc/pam_url
MYAUTH=/usr/local/etc/myauth
APACHE2_USER=www-data
EXPERIMENTAL=/usr/local/experimental

all: ${obj}

debug:
	CFLAGS="-g3 -O0" ${MAKE} all

${obj}: ${objo} aux.h
	${CC} ${objo} ${LDFLAGS} -o ${obj}

clean:
	rm -f ${obj} ${objo}

install:
	install -D -m 755 ${obj} ${DESTDIR}/${pamlib}/${obj}
	test -s ${DESTDIR}/etc/pam_url.conf || install -D -m 644 examples/pam_url.conf ${DESTDIR}/etc/pam_url.conf

experimental:
	umask 077
	mkdir -p ${PAM_URL} && touch ${PAM_URL}/secret && chmod 0400 ${PAM_URL}/secret
	mkdir -p ${MYAUTH} && chmod 700 ${MYAUTH} && touch ${MYAUTH}/secret && chmod 0400 ${MYAUTH}/secret \
		&& echo "0" > ${MYAUTH}/serial && chown -R ${APACHE2_USER} ${MYAUTH}
	openssl rand -base64 48 | tee ${PAM_URL}/secret > ${MYAUTH}/secret
	mkdir -p ${EXPERIMENTAL}/etc ${EXPERIMENTAL}/lib
	install -D -m 500 ${obj} ${EXPERIMENTAL}/lib/
	install -m 511 examples/experimental/myauth-hmac.php /usr/lib/cgi-bin
	test -s ${EXPERIMENTAL}/etc/pam_url.conf || install -D -m 644 examples/experimental/pam_url.conf ${EXPERIMENTAL}/etc
	install -m 644 examples/experimental/pam_url_test /etc/pam.d
	mkdir /var/lib/pam_url

reinit:
	echo "0" > /var/lib/pam_url/serial && echo "0" > /var/lib/pam_url/nonce_ctr

secret:
	openssl rand -base64 48 | tee ${PAM_URL}/secret > ${MYAUTH}/secret

uninstall:
	rm -f ${DESTDIR}/${pamlib}/${obj}
