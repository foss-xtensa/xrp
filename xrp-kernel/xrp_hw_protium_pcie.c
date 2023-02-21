/*
 * xrp_hw_protium_pcie: PCIe protium low-level XRP driver
 *
 * Copyright (c) 2020 Cadence Design Systems, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Alternatively you can use and distribute this file under the terms of
 * the GNU General Public License version 2 or later.
 */

#include <linux/delay.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "xrp_kernel_defs.h"
#include "xrp_hw.h"
#include "xrp_hw_simple_dsp_interface.h"

#define DRIVER_NAME "xrp-hw-protium-pcie"

#define CORE0_CONTROL				0x00000010
#define CORE0_CONTROL_BRESET			0x01
#define CORE0_CONTROL_RUNSTALL			0x02
#define CORE0_CONTROL_OCD_HALT_ON_RESET		0x04
#define CORE0_CONTROL_STAT_VECTOR_SEL		0x10

#define CORE0_IRQ_REQ				0x00000020

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
#define xrp_write_access_ok(addr, sz) \
	(access_ok(VERIFY_WRITE, (void __user *)(vaddr), (sz)))
#define xrp_read_access_ok(addr, sz) \
	(access_ok(VERIFY_READ, (void __user *)(vaddr), (sz)))
#else
#define xrp_write_access_ok(addr, sz) \
	(access_ok((void __user *)(vaddr), (sz)))
#define xrp_read_access_ok(addr, sz) \
	(access_ok((void __user *)(vaddr), (sz)))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#define kernel_read(filp, vaddr, size, poff) \
	kernel_read((filp), *(poff), (vaddr), (size))
#define kernel_write(filp, vaddr, size, poff) \
	kernel_write((filp), (vaddr), (size), *(poff))
#else
#endif

enum xrp_irq_mode {
	XRP_IRQ_NONE,
	XRP_IRQ_LEVEL,
	XRP_IRQ_EDGE,
	XRP_IRQ_EDGE_SW,
	XRP_IRQ_MAX,
};

static int xdma_instance = 0;
module_param(xdma_instance, int, 0644);
MODULE_PARM_DESC(xdma_instance, "Specify XDMA instance to open. The default is 0 (int).");

static uint shared_mem_loc[2] = {0x80000000, 0x87ffffff};
module_param_array(shared_mem_loc, uint, NULL, 0644);
MODULE_PARM_DESC(shared_mem_loc, "Array of IO_RESOUCE_MEM start/end. The default is {0x80000000, 0x87fffffff}.");

static int stat_vector_sel = 0;
module_param(stat_vector_sel, int, 0644);
MODULE_PARM_DESC(stat_vector_sel, "StatVectorSel. The default is 0 (int).");

struct xrp_hw_protium {
	struct xvp *xrp;
	phys_addr_t regs_phys;

	/* how IRQ is used to notify the device of incoming data */
	enum xrp_irq_mode device_irq_mode;
	/*
	 * offset of device IRQ register in MMIO region (device side)
	 * bit number
	 * device IRQ#
	 */
	u32 device_irq[3];
	/* how IRQ is used to notify the host of incoming data */
	enum xrp_irq_mode host_irq_mode;
	/*
	 * offset of IRQ register (device side)
	 * bit number
	 */
	u32 host_irq[2];

	struct file *write_filp;
	struct file *read_filp;

	/* shadow copy of AXI registers */
	u32 core0_control;

	void *scratch;
};

static long write_axi(struct xrp_hw_protium *hw,
		      const void *vaddr, unsigned long sz,
		      phys_addr_t paddr)
{
	loff_t pos = paddr;
	ssize_t written;

	pr_debug("%s: vaddr = %08lx, sz = %08lx, paddr = %pap\n",
		 __func__, (unsigned long)vaddr, sz, &paddr);
	written = kernel_write(hw->write_filp, vaddr, sz, &pos);
	if (written == sz)
		return 0;
	return -EINVAL;
}

static long read_axi(struct xrp_hw_protium *hw,
		      void *vaddr, unsigned long sz,
		      phys_addr_t paddr)
{
	loff_t pos = paddr;
	ssize_t read;

	pr_debug("%s: vaddr = %08lx, sz = %08lx, paddr = %pap\n",
		 __func__, (unsigned long)vaddr, sz, &paddr);
	read = kernel_read(hw->read_filp, vaddr, sz, &pos);
	if (read == sz)
		return 0;
	return -EINVAL;
}

static inline void reg_write32(struct xrp_hw_protium *hw, unsigned addr, u32 v)
{
	if (hw->write_filp && addr + sizeof(v) <= PAGE_SIZE) {
		memcpy(hw->scratch + addr, &v, sizeof(v));
		write_axi(hw, hw->scratch + addr, sizeof(v), addr);
	}
}

static inline u32 reg_read32(struct xrp_hw_protium *hw, unsigned addr)
{
	u32 v = 0;

	if (hw->read_filp && addr + sizeof(v) <= PAGE_SIZE) {
		read_axi(hw, hw->scratch + addr, sizeof(v), addr);
		memcpy(&v, hw->scratch + addr, sizeof(v));
	}
	return v;
}

static void *get_hw_sync_data(void *hw_arg, size_t *sz)
{
	static const u32 irq_mode[] = {
		[XRP_IRQ_NONE] = XRP_DSP_SYNC_IRQ_MODE_NONE,
		[XRP_IRQ_LEVEL] = XRP_DSP_SYNC_IRQ_MODE_LEVEL,
		[XRP_IRQ_EDGE] = XRP_DSP_SYNC_IRQ_MODE_EDGE,
		[XRP_IRQ_EDGE_SW] = XRP_DSP_SYNC_IRQ_MODE_EDGE,
	};
	struct xrp_hw_protium *hw = hw_arg;
	struct xrp_hw_simple_sync_data *hw_sync_data =
		kmalloc(sizeof(*hw_sync_data), GFP_KERNEL);

	if (!hw_sync_data)
		return NULL;

	*hw_sync_data = (struct xrp_hw_simple_sync_data){
		.device_mmio_base = hw->regs_phys,
		.host_irq_mode = hw->host_irq_mode,
		.host_irq_offset = hw->host_irq[0],
		.host_irq_bit = hw->host_irq[1],
		.device_irq_mode = irq_mode[hw->device_irq_mode],
		.device_irq_offset = hw->device_irq[0],
		.device_irq_bit = hw->device_irq[1],
		.device_irq = hw->device_irq[2],
	};
	*sz = sizeof(*hw_sync_data);
	return hw_sync_data;
}

static void xrp_hw_protium_reset(void *hw_arg)
{
	struct xrp_hw_protium *hw = hw_arg;
	pr_debug("%s: hw->core0_control=0x%08x\n", __func__, hw->core0_control);

	if (stat_vector_sel) {
		pr_debug("%s: using StatVectoSel\n", __func__);
		hw->core0_control |= CORE0_CONTROL_STAT_VECTOR_SEL;
		reg_write32(hw_arg, CORE0_CONTROL, hw->core0_control);
		udelay(1);
	}

	reg_write32(hw_arg, CORE0_CONTROL,
		    hw->core0_control | CORE0_CONTROL_BRESET);
	udelay(1);
	reg_write32(hw_arg, CORE0_CONTROL, hw->core0_control);
	pr_debug("%s: hw->core0_control=0x%08x\n", __func__, hw->core0_control);
}

static void xrp_hw_protium_halt(void *hw_arg)
{
	struct xrp_hw_protium *hw = hw_arg;
	pr_debug("%s: hw->core0_control=0x%08x\n", __func__, hw->core0_control);

	hw->core0_control |= CORE0_CONTROL_RUNSTALL;
	reg_write32(hw_arg, CORE0_CONTROL, hw->core0_control);
	pr_debug("%s: hw->core0_control=0x%08x\n", __func__, hw->core0_control);
}

static void xrp_hw_protium_release(void *hw_arg)
{
	struct xrp_hw_protium *hw = hw_arg;
	pr_debug("%s: hw->core0_control=0x%08x\n", __func__, hw->core0_control);

	hw->core0_control &= ~CORE0_CONTROL_RUNSTALL;
	reg_write32(hw_arg, CORE0_CONTROL, hw->core0_control);
	pr_debug("%s: hw->core0_control=0x%08x\n", __func__, hw->core0_control);
}

static void send_irq(void *hw_arg)
{
	struct xrp_hw_protium *hw = hw_arg;
	pr_debug("%s\n", __func__);

	switch (hw->device_irq_mode) {
	case XRP_IRQ_EDGE:
		reg_write32(hw, CORE0_IRQ_REQ, 0);
		/* fallthrough */
	case XRP_IRQ_LEVEL:
		wmb();
		reg_write32(hw, CORE0_IRQ_REQ,
			    BIT(hw->device_irq[1]));
		break;
	default:
		break;
	}
}

static void ack_irq(void *hw_arg)
{
	struct xrp_hw_protium *hw = hw_arg;

	if (hw->host_irq_mode == XRP_IRQ_LEVEL)
		reg_write32(hw, hw->host_irq[0], 0);
}

static irqreturn_t irq_handler(int irq, void *dev_id)
{
	struct xrp_hw_protium *hw = dev_id;
	irqreturn_t ret = xrp_irq_handler(irq, hw->xrp);

	if (ret == IRQ_HANDLED)
		ack_irq(hw);

	return ret;
}

static long load_fw_segment(void *hw_arg, const void *image, Elf32_Phdr *phdr)
{
	unsigned long filesz = ALIGN(phdr->p_filesz, 4);
	unsigned long memsz = ALIGN(phdr->p_memsz, 4);
	void *p = vmalloc_32(memsz);
	long rc;

	if (!p) {
		pr_err("%s: no memory\n", __func__);
		return -ENOMEM;
	}
	memcpy(p, image + phdr->p_offset, filesz);
	memset(p + filesz, 0, memsz - filesz);
	rc = write_axi(hw_arg, p, memsz, phdr->p_paddr);
	if (rc < 0)
		pr_err("%s: error copying segment data\n", __func__);

	vfree(p);
	return rc;
}

static void *alloc_host(void *hw_arg, size_t sz)
{
	return vmalloc_32(sz);
}

static void free_host(void *hw_arg, void *p)
{
	return vfree(p);
}

static long copy_to_alloc(void *hw_arg,
			  const void *p, unsigned long sz,
			  phys_addr_t paddr)
{
	return write_axi(hw_arg, p, sz, paddr);
}

static long copy_from_alloc(void *hw_arg,
			    void *p, unsigned long sz,
			    phys_addr_t paddr)
{
	return read_axi(hw_arg, p, sz, paddr);
}

static long copy_to_alloc_user(void *hw_arg,
			       unsigned long vaddr, unsigned long sz,
			       phys_addr_t paddr)
{
	if (xrp_read_access_ok(vaddr, sz))
		return write_axi(hw_arg, (void *)vaddr, sz, paddr);
	else
		return -EINVAL;
}

static long copy_from_alloc_user(void *hw_arg,
				 unsigned long vaddr, unsigned long sz,
				 phys_addr_t paddr)
{
	if (xrp_write_access_ok(vaddr, sz))
		return read_axi(hw_arg, (void *)vaddr, sz, paddr);
	else
		return -EINVAL;
}

static long property_read_string(void *hw_arg,
				 const char *name,
				 const char **val)
{
	if (strcmp(name, "firmware-name") == 0) {
		*val = "xrp.elf";
		return 0;
	} else {
		return -ENODATA;
	}
}

static long property_read_u32_array(void *hw_arg,
				    const char *name,
				    u32 *val, size_t nval)
{
	if (strcmp(name, "queue-priority") == 0) {
		static const u32 qp[] = {
			4, 5, 6,
		};
		if (!val)
			return ARRAY_SIZE(qp);
		if (nval > ARRAY_SIZE(qp)) {
			memset(val + ARRAY_SIZE(qp), 0,
			       (nval - ARRAY_SIZE(qp)) * sizeof(u32));
			nval = ARRAY_SIZE(qp);
		}
		memcpy(val, qp, nval * sizeof(u32));
		return 0;
	} else {
		return -ENODATA;
	}
}

static const struct xrp_hw_ops hw_ops = {
	.halt = xrp_hw_protium_halt,
	.release = xrp_hw_protium_release,
	.reset = xrp_hw_protium_reset,

	.get_hw_sync_data = get_hw_sync_data,

	.send_irq = send_irq,

	.load_fw_segment = load_fw_segment,
	.alloc_host = alloc_host,
	.free_host = free_host,
	.copy_to_alloc = copy_to_alloc,
	.copy_from_alloc = copy_from_alloc,
	.copy_to_alloc_user = copy_to_alloc_user,
	.copy_from_alloc_user = copy_from_alloc_user,

	.property_read_string = property_read_string,
	.property_read_u32_array = property_read_u32_array,
};

static long init_hw(struct platform_device *pdev, struct xrp_hw_protium *hw,
		    int mem_idx, enum xrp_init_flags *init_flags)
{
	int irq;
	long ret;
	struct file *write_filp;
	struct file *read_filp;
	u32 v;
	char h2c[32];
	char c2h[32];
	struct resource *r;

	hw->scratch = vmalloc(PAGE_SIZE);
	if (!hw->scratch)
		return -ENOMEM;

	snprintf(h2c, 32, "/dev/xdma%d_h2c_0", xdma_instance);
	snprintf(c2h, 32, "/dev/xdma%d_c2h_0", xdma_instance);
	pr_debug("write_filp: %s", h2c);
	pr_debug("read_filp: %s", c2h);

	write_filp = filp_open(h2c, O_WRONLY, 0);
	read_filp = filp_open(c2h, O_RDONLY, 0);
	if (IS_ERR(write_filp)) {
		ret = PTR_ERR(write_filp);
		goto err;
	}
	if (IS_ERR(read_filp)) {
		ret = PTR_ERR(read_filp);
		goto err;
	}
	hw->write_filp = write_filp;
	hw->read_filp = read_filp;

	v = reg_read32(hw, 0);
	dev_info(&pdev->dev, "FPGA build version: %08x\n", v);

#if 0
	ret = of_property_read_u32_array(pdev->dev.of_node,
					 "device-irq",
					 hw->device_irq,
					 ARRAY_SIZE(hw->device_irq));
	if (ret == 0) {
		u32 device_irq_mode;

		ret = of_property_read_u32(pdev->dev.of_node,
					   "device-irq-mode",
					   &device_irq_mode);
		if (device_irq_mode < XRP_IRQ_MAX)
			hw->device_irq_mode = device_irq_mode;
		else
			ret = -ENOENT;
	}
#else
	hw->device_irq[0] = CORE0_IRQ_REQ;
	hw->device_irq[1] = 0;
	hw->device_irq[2] = 0;
	hw->device_irq_mode = XRP_IRQ_LEVEL;
	ret = 0;
#endif
	if (ret == 0) {
		dev_dbg(&pdev->dev,
			"%s: device IRQ MMIO offset = 0x%08x, bit = %d, device IRQ = %d, IRQ mode = %d",
			__func__,
			hw->device_irq[0], hw->device_irq[1],
			hw->device_irq[2], hw->device_irq_mode);
	} else {
		dev_info(&pdev->dev,
			 "using polling mode on the device side\n");
	}

	ret = of_property_read_u32_array(pdev->dev.of_node, "host-irq",
					 hw->host_irq,
					 ARRAY_SIZE(hw->host_irq));
	if (ret == 0) {
		u32 host_irq_mode;

		ret = of_property_read_u32(pdev->dev.of_node,
					   "host-irq-mode",
					   &host_irq_mode);
		if (host_irq_mode < XRP_IRQ_MAX)
			hw->host_irq_mode = host_irq_mode;
		else
			ret = -ENOENT;
	}

	if (ret == 0 && hw->host_irq_mode != XRP_IRQ_NONE)
		irq = platform_get_irq(pdev, 0);
	else
		irq = -1;

	if (irq >= 0) {
		dev_dbg(&pdev->dev, "%s: host IRQ = %d, ",
			__func__, irq);
		ret = devm_request_irq(&pdev->dev, irq, irq_handler,
				       IRQF_SHARED, pdev->name, hw);
		if (ret < 0) {
			dev_err(&pdev->dev, "request_irq %d failed\n", irq);
			goto err;
		}
		*init_flags |= XRP_INIT_USE_HOST_IRQ;
	} else {
		dev_info(&pdev->dev, "using polling mode on the host side\n");
	}
	ret = 0;

	r = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	r->start = shared_mem_loc[0];
	r->end = shared_mem_loc[1];
	pr_debug("shared mem start: 0x%8x\n", (uint)r->start);
	pr_debug("shared mem end: 0x%8x\n", (uint)r->end);

	return ret;

err:
	if (!IS_ERR(write_filp))
		fput(write_filp);
	if (!IS_ERR(read_filp))
		fput(read_filp);
	if (hw->scratch)
		vfree(hw->scratch);
	return ret;

}

static long init_v1(struct platform_device *pdev, struct xrp_hw_protium *hw)
{
	long ret;
	enum xrp_init_flags init_flags = XRP_INIT_NO_DIRECT_MAPPING;

	ret = init_hw(pdev, hw, 1, &init_flags);
	if (ret < 0)
		return ret;

	return xrp_init_v1(pdev, init_flags, &hw_ops, hw);
}

static int xrp_hw_protium_probe(struct platform_device *pdev)
{
	struct xrp_hw_protium *hw =
		devm_kzalloc(&pdev->dev, sizeof(*hw), GFP_KERNEL);
	long ret;

	if (!hw)
		return -ENOMEM;

	ret = init_v1(pdev, hw);
	if (!IS_ERR_VALUE(ret)) {
		hw->xrp = ERR_PTR(ret);
		ret = 0;
	}

	return ret;
}

static int xrp_hw_protium_remove(struct platform_device *pdev)
{
	struct xrp_hw_protium *hw;

	xrp_deinit_hw(pdev, (void **)&hw);
	fput(hw->write_filp);
	fput(hw->read_filp);
	vfree(hw->scratch);
	return 0;
}

static const struct dev_pm_ops xrp_hw_protium_pm_ops = {
	SET_RUNTIME_PM_OPS(xrp_runtime_suspend,
			   xrp_runtime_resume, NULL)
};

static struct platform_driver xrp_hw_protium_pcie_driver = {
	.probe   = xrp_hw_protium_probe,
	.remove  = xrp_hw_protium_remove,
	.driver  = {
		.name = DRIVER_NAME,
		.pm = &xrp_hw_protium_pm_ops,
	},
};

static struct resource xrp_hw_protium_pcie_res[] = {
	{
		.start = 0x80000000,
		.end = 0x87ffffff,
		.flags = IORESOURCE_MEM,
	},
};

static struct platform_device xrp_hw_protium_pcie_device = {
	.name		= DRIVER_NAME,
	.id		= -1,
	.num_resources	= ARRAY_SIZE(xrp_hw_protium_pcie_res),
	.resource	= xrp_hw_protium_pcie_res,
	.dev		= {
		//.platform_data = xrp_protium_device_data,
	},
};

static int __init xrp_hw_protium_pcie_devinit(void)
{
	platform_driver_register(&xrp_hw_protium_pcie_driver);
	platform_device_register(&xrp_hw_protium_pcie_device);
	return 0;
}

device_initcall(xrp_hw_protium_pcie_devinit);

MODULE_AUTHOR("Max Filippov");
MODULE_DESCRIPTION("XRP: low level device driver for Xtensa Remote Processing");
MODULE_LICENSE("Dual MIT/GPL");
