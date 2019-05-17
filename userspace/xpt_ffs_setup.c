/**
 * @file xpt_ffs_setup.c
 *
 * Application for setting up a linux gadget device using a composite configfs / functionfs
 * Current configuration creates a functionfs ep1 ep2 for in out communication
 * and a default network interface gadget as a composite usb device.
 *
 * To create the configfs setup we use libusbg
 * @note This program only does the configuration of the system, enabling the gadget needs to be done later on, after the
 *       functionfs deamon is started.
 *
 * @note To use this configuration the following needs to be done after running this program
 *  => cd /functionfs && ffs-testd &
 *  Now we can start
 *  => echo "my_udc_name" > /sys/kernel/config/usb_gadget/g1/UDC
 */


#include <stdlib.h>
#include <errno.h>
#include <stdio.h>

#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <usbg/usbg.h>

/**
 *  Configuration definitions
 */

#define VENDOR	0x1d6b
#define PRODUCT	0x0104

#define FUNCTIONFS_MOUNT_POINT "/functionfs/"

/**
 * Function setting the actual gadget configuration
 */
int setup_gadget_config()
{
	usbg_state *s;
	usbg_gadget *g;
	usbg_config *c;
	usbg_function *f_ffs0, *f_rndis0;
	int ret = -EINVAL;
	int usbg_ret;

	struct usbg_gadget_attrs g_attrs = {
			0x0200, /* bcdUSB */
			0x00, /* Defined at interface level */
			0x00, /* subclass */
			0x00, /* device protocol */
			0x0040, /* Max allowed packet size */
			VENDOR,
			PRODUCT,
			0x0001, /* Version of device */
	};

	struct usbg_gadget_strs g_strs = {
			"Xaptum", /* Manufacturer */
			"0123456789", /* Serial number */
			"Xpt Product " /* Product string */
	};

	usbg_ret = usbg_init("/sys/kernel/config", &s);
	if (usbg_ret != USBG_SUCCESS) {
		fprintf(stderr, "Error on USB gadget init\n");
		fprintf(stderr, "Error: %s : %s\n", usbg_error_name(usbg_ret),
				usbg_strerror(usbg_ret));
		goto out1;
	}

	usbg_ret = usbg_create_gadget(s, "g1", &g_attrs, &g_strs, &g);
	if (usbg_ret != USBG_SUCCESS) {
		fprintf(stderr, "Error on create gadget\n");
		fprintf(stderr, "Error: %s : %s\n", usbg_error_name(usbg_ret),
				usbg_strerror(usbg_ret));
		goto out2;
	}

	usbg_ret = usbg_create_function(g, USBG_F_FFS, "cfg0", NULL, &f_ffs0);
	if (usbg_ret != USBG_SUCCESS) {
		fprintf(stderr, "Error creating acm0 function\n");
		fprintf(stderr, "Error: %s : %s\n", usbg_error_name(usbg_ret),
				usbg_strerror(usbg_ret));
		goto out2;
	}

	usbg_ret = usbg_create_function(g, USBG_F_RNDIS, "usb0", NULL, &f_rndis0);
	if (usbg_ret != USBG_SUCCESS) {
		fprintf(stderr, "Error creating acm1 function\n");
		fprintf(stderr, "Error: %s : %s\n", usbg_error_name(usbg_ret),
				usbg_strerror(usbg_ret));
		goto out2;
	}

	/* NULL can be passed to use kernel defaults */
	usbg_ret = usbg_create_config(g, 1, "The only one", NULL, NULL, &c);
	if (usbg_ret != USBG_SUCCESS) {
		fprintf(stderr, "Error creating config\n");
		fprintf(stderr, "Error: %s : %s\n", usbg_error_name(usbg_ret),
				usbg_strerror(usbg_ret));
		goto out2;
	}

	usbg_ret = usbg_add_config_function(c, "usbfunc0", f_ffs0);
	if (usbg_ret != USBG_SUCCESS) {
		fprintf(stderr, "Error ffs usbfunc0\n");
		fprintf(stderr, "Error: %s : %s\n", usbg_error_name(usbg_ret),
				usbg_strerror(usbg_ret));
		goto out2;
	}

	usbg_ret = usbg_add_config_function(c, "rndis.usb0", f_rndis0);
	if (usbg_ret != USBG_SUCCESS) {
		fprintf(stderr, "Error addingrndis.usb0\n");
		fprintf(stderr, "Error: %s : %s\n", usbg_error_name(usbg_ret),
				usbg_strerror(usbg_ret));
		goto out2;
	}

	ret = 0;

out2:
	usbg_cleanup(s);

out1:
	return ret;

}

/**
 * Function to mount the functionfs filesystem so we can start the deamon there later on
 */
int mount_function_fs()
{
	int ret;

	// Create mount point if not already there
	struct stat st = {0};
	if (stat(FUNCTIONFS_MOUNT_POINT, &st) == -1)
	{
	    mkdir(FUNCTIONFS_MOUNT_POINT, 0700);
	}

	// Mount the functionfs filesystem
	const char* src  = "cfg0";
	const char* trgt = FUNCTIONFS_MOUNT_POINT;
	const char* type = "functionfs";
	const unsigned long mntflags = 0;
	const char* opts = "";
    ret = mount(src, trgt, type, mntflags, opts);

	return ret;
}

/**
 * Application main
 */
int main()
{
		int ret;
		ret = setup_gadget_config();

		ret = mount_function_fs();

		return ret;
}
