# in-tree kernel variable.
obj-m := tcp_cubic++.o

EXTRA_CFLAGS := -Werror

# out-of-tree rules.
DIR=	/lib/modules/`uname -r`/build
all:
	make -C $(DIR) M=$(PWD) modules
clean:
	make -C $(DIR) M=$(PWD) clean
