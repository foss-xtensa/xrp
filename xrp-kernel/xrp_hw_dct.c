/*
 * xrp_hw_dct: Simple xtensa/arm low-level XRP driver
 *
 * Copyright (c) 2017 Cadence Design Systems, Inc.
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
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/mfd/syscon.h>
#include <linux/regmap.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <asm/cacheflush.h>
#include "xrp_hw.h"
#include "xrp_hw_dct_dsp_interface.h"
#include "xrp_internal.h"

#define DRIVER_NAME "xrp-hw-dct"

enum xrp_irq_mode {
	XRP_IRQ_NONE,
	XRP_IRQ_LEVEL,
	XRP_IRQ_EDGE,
	XRP_IRQ_MAX,
};

struct xrp_hw_dct {
	struct xvp xrp;
  phys_addr_t device_mmio_base;

  struct regmap *dsp_ctrl;
  struct regmap *scu_ctrl;

	/* how IRQ is used to notify the device of incoming data */
	enum xrp_irq_mode device_irq_mode;
	/*
	 * offset of device IRQ register in MMIO region (device side)
	 * bit number
	 * device IRQ#
	 */
	u32 device_irq_ism[2];
	u32 device_irq_ris[2];
	u32 device_irq_mis[2];
	u32 device_irq_isc[2];
	u32 device_irq_iss[2];
	u32 device_irq;

	/* how IRQ is used to notify the host of incoming data */
	enum xrp_irq_mode host_irq_mode;
	/*
	 * offset of IRQ register (device side)
	 * bit number
	 */
	u32 host_irq_ism[2];
	u32 host_irq_ris[2];
	u32 host_irq_mis[2];
	u32 host_irq_isc[2];
	u32 host_irq_iss[2];
	u32 host_irq[2];

  u32 dsp_reset[2];
  u32 dsp_runstall[2];
};

static inline void reg_bitset32(struct regmap *reg, u32 ofst, u32 bit)
{
  u32 mask = (0x1 << bit);
  regmap_update_bits(reg, ofst, mask, mask);
}

static inline void reg_bitclr32(struct regmap *reg, u32 ofst, u32 bit)
{
  u32 mask = (0x1 << bit);
  regmap_update_bits(reg, ofst, mask, 0);
}


static void *get_hw_sync_data(void *hw_arg, size_t *sz)
{
	struct xrp_hw_dct *hw = hw_arg;
	struct xrp_hw_dct_sync_data *hw_sync_data =
		kmalloc(sizeof(*hw_sync_data), GFP_KERNEL);

	if (!hw_sync_data)
		return NULL;

  //prepare info struct for DSP
	*hw_sync_data = (struct xrp_hw_dct_sync_data){
		.device_mmio_base = hw->device_mmio_base,
		.device_irq_ism[0] = hw->device_irq_ism[0],
		.device_irq_ism[1] = hw->device_irq_ism[1],
		.device_irq_ris[0] = hw->device_irq_ris[0],
		.device_irq_ris[1] = hw->device_irq_ris[1],
		.device_irq_mis[0] = hw->device_irq_mis[0],
		.device_irq_mis[1] = hw->device_irq_mis[1],
		.device_irq_isc[0] = hw->device_irq_isc[0],
		.device_irq_isc[1] = hw->device_irq_isc[1],
		.device_irq_iss[0] = hw->device_irq_iss[0],
		.device_irq_iss[1] = hw->device_irq_iss[1],
		.device_irq_mode = hw->device_irq_mode,
		.device_irq = hw->device_irq,

		.host_irq_ism[0] = hw->host_irq_ism[0],
		.host_irq_ism[1] = hw->host_irq_ism[1],
		.host_irq_ris[0] = hw->host_irq_ris[0],
		.host_irq_ris[1] = hw->host_irq_ris[1],
		.host_irq_mis[0] = hw->host_irq_mis[0],
		.host_irq_mis[1] = hw->host_irq_mis[1],
		.host_irq_isc[0] = hw->host_irq_isc[0],
		.host_irq_isc[1] = hw->host_irq_isc[1],
		.host_irq_iss[0] = hw->host_irq_iss[0],
		.host_irq_iss[1] = hw->host_irq_iss[1],
		.host_irq_mode = hw->host_irq_mode
	};
	*sz = sizeof(*hw_sync_data);
	return hw_sync_data;
}

static void reset(void *hw_arg)
{
  struct xrp_hw_dct *hw = hw_arg;

  //reset is active-low, so 'bitclr' is reset, 'biset' is normal op
  reg_bitclr32(hw->scu_ctrl, hw->dsp_reset[0], hw->dsp_reset[1]);
	udelay(1);
  reg_bitset32(hw->scu_ctrl, hw->dsp_reset[0], hw->dsp_reset[1]);
}

static void halt(void *hw_arg)
{
  struct xrp_hw_dct *hw = hw_arg;
  reg_bitset32(hw->scu_ctrl, hw->dsp_runstall[0], hw->dsp_runstall[1]);
}

static void release(void *hw_arg)
{
  struct xrp_hw_dct *hw = hw_arg;
  reg_bitclr32(hw->scu_ctrl, hw->dsp_runstall[0], hw->dsp_runstall[1]);
}

static void send_irq(void *hw_arg)
{
	struct xrp_hw_dct *hw = hw_arg;

	switch (hw->device_irq_mode) {
	case XRP_IRQ_EDGE:
    reg_bitset32(hw->dsp_ctrl, hw->device_irq_iss[0], hw->device_irq_iss[1]);
	  udelay(1);
    reg_bitset32(hw->dsp_ctrl, hw->device_irq_isc[0], hw->device_irq_isc[1]);
		/* fallthrough */
	case XRP_IRQ_LEVEL:
		wmb();
    reg_bitset32(hw->dsp_ctrl, hw->device_irq_iss[0], hw->device_irq_iss[1]);
		break;
	default:
		break;
	}
}

static void ack_irq(void *hw_arg)
{
	struct xrp_hw_dct *hw = hw_arg;

	if (hw->host_irq_mode == XRP_IRQ_LEVEL)
    reg_bitset32(hw->dsp_ctrl, hw->device_irq_isc[0], hw->device_irq_isc[1]);
}

static irqreturn_t irq_handler(int irq, void *dev_id)
{
	struct xrp_hw_dct *hw = dev_id;
	irqreturn_t ret = xrp_irq_handler(irq, &hw->xrp);

	if (ret == IRQ_HANDLED)
		ack_irq(hw);

	return ret;
}

#if defined(__XTENSA__)
static void clean_cache(void *vaddr, phys_addr_t paddr, unsigned long sz)
{
	__flush_dcache_range((unsigned long)vaddr, sz);
}

static void flush_cache(void *vaddr, phys_addr_t paddr, unsigned long sz)
{
	__flush_dcache_range((unsigned long)vaddr, sz);
	__invalidate_dcache_range((unsigned long)vaddr, sz);
}

static void invalidate_cache(void *vaddr, phys_addr_t paddr, unsigned long sz)
{
	__invalidate_dcache_range((unsigned long)vaddr, sz);
}
#elif defined(__arm__)
static void clean_cache(void *vaddr, phys_addr_t paddr, unsigned long sz)
{
	__cpuc_flush_dcache_area(vaddr, sz);
	outer_clean_range(paddr, paddr + sz);
}

static void flush_cache(void *vaddr, phys_addr_t paddr, unsigned long sz)
{
	__cpuc_flush_dcache_area(vaddr, sz);
	outer_flush_range(paddr, paddr + sz);
}

static void invalidate_cache(void *vaddr, phys_addr_t paddr, unsigned long sz)
{
	__cpuc_flush_dcache_area(vaddr, sz);
	outer_inv_range(paddr, paddr + sz);
}
#else
#warning "cache operations are not implemented for this architecture"
static void clean_cache(void *vaddr, phys_addr_t paddr, unsigned long sz)
{
}

static void flush_cache(void *vaddr, phys_addr_t paddr, unsigned long sz)
{
}

static void invalidate_cache(void *vaddr, phys_addr_t paddr, unsigned long sz)
{
}
#endif

static const struct xrp_hw_ops hw_ops = {
	.halt = halt,
	.release = release,
	.reset = reset,

	.get_hw_sync_data = get_hw_sync_data,

	.send_irq = send_irq,

	.clean_cache = clean_cache,
	.flush_cache = flush_cache,
	.invalidate_cache = invalidate_cache,
};

static int init_hw_dct(struct platform_device *pdev, struct xrp_hw_dct *hw,
		   int mem_idx)
{
  struct resource *mem;
	int irq;
	int ret;

  hw->dsp_ctrl = syscon_regmap_lookup_by_compatible("dct,dct-dsp-ctrl");
  if (IS_ERR(hw->dsp_ctrl)) {
    dev_err(&pdev->dev, "unable to get dsp ctrl regmap");
    return PTR_ERR(hw->dsp_ctrl);
  }

  hw->scu_ctrl = syscon_regmap_lookup_by_compatible("dct,dct-dsp-syscon");
  if (IS_ERR(hw->scu_ctrl)) {
    dev_err(&pdev->dev, "unable to get scu ctrl regmap");
    return PTR_ERR(hw->scu_ctrl);
  }

#if 0
  mem = platform_get_resource(pdev, IORESOURCE_MEM, mem_idx);
  if (mem) {
    hw->device_mmio_base = mem->start;
  } else {
  }

#endif

	u32 device_mmio_base;
	ret = of_property_read_u32(pdev->dev.of_node,
					 "device-mmio-base",
            &device_mmio_base);
   
  if (ret < 0) {
    dev_err(&pdev->dev, "device_mmio_base not specified\n");
    goto err;
  }
	hw->device_mmio_base = device_mmio_base;

	ret = of_property_read_u32(pdev->dev.of_node,
					 "device-irq",
					 &hw->device_irq);
	if (ret == 0) {
		ret = of_property_read_u32_array(pdev->dev.of_node,
						 "device-irq-ism",
						 hw->device_irq_ism,
						 ARRAY_SIZE(hw->device_irq_ism));
  }
	if (ret == 0) {
		ret = of_property_read_u32_array(pdev->dev.of_node,
						 "device-irq-ris",
						 hw->device_irq_ris,
						 ARRAY_SIZE(hw->device_irq_ris));
  }
	if (ret == 0) {
		ret = of_property_read_u32_array(pdev->dev.of_node,
						 "device-irq-mis",
						 hw->device_irq_mis,
						 ARRAY_SIZE(hw->device_irq_mis));
  }
	if (ret == 0) {
		ret = of_property_read_u32_array(pdev->dev.of_node,
						 "device-irq-isc",
						 hw->device_irq_isc,
						 ARRAY_SIZE(hw->device_irq_isc));
  }
	if (ret == 0) {
		ret = of_property_read_u32_array(pdev->dev.of_node,
						 "device-irq-iss",
						 hw->device_irq_iss,
						 ARRAY_SIZE(hw->device_irq_iss));
  }
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
	if (ret == 0) {
		dev_dbg(&pdev->dev,
			"%s: device IRQ set offset = 0x%08x, set bit = %d, clear offset = 0x%08x, clear bit = %d, device IRQ = %d, IRQ mode = %d",
			__func__, hw->device_irq_iss[0], hw->device_irq_iss[1],
			          hw->device_irq_isc[0], hw->device_irq_isc[1],  
			          hw->device_irq, hw->device_irq_mode);
	} else {
		dev_info(&pdev->dev,
			 "using polling mode on the device side\n");
	}

  //host
	ret = of_property_read_u32_array(pdev->dev.of_node, "host-irq",
					 hw->host_irq,
					 ARRAY_SIZE(hw->host_irq));
	if (ret == 0) {
	  ret = of_property_read_u32_array(pdev->dev.of_node, "host-irq-ism",
		  			 hw->host_irq_ism,
			  		 ARRAY_SIZE(hw->host_irq_ism));
  }
	if (ret == 0) {
	  ret = of_property_read_u32_array(pdev->dev.of_node, "host-irq-ris",
		  			 hw->host_irq_ris,
			  		 ARRAY_SIZE(hw->host_irq_ris));
  }
	if (ret == 0) {
	  ret = of_property_read_u32_array(pdev->dev.of_node, "host-irq-mis",
		  			 hw->host_irq_mis,
			  		 ARRAY_SIZE(hw->host_irq_mis));
  }
	if (ret == 0) {
	  ret = of_property_read_u32_array(pdev->dev.of_node, "host-irq-isc",
		  			 hw->host_irq_isc,
			  		 ARRAY_SIZE(hw->host_irq_isc));
  }
	if (ret == 0) {
	  ret = of_property_read_u32_array(pdev->dev.of_node, "host-irq-iss",
		  			 hw->host_irq_iss,
			  		 ARRAY_SIZE(hw->host_irq_iss));
  }
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
	irq = platform_get_irq(pdev, 0);
	if (irq >= 0 && ret == 0) {
		dev_dbg(&pdev->dev, "%s: host IRQ = %d, ",
			__func__, irq);
		ret = devm_request_irq(&pdev->dev, irq, irq_handler,
				       IRQF_SHARED, pdev->name, hw);
		if (ret < 0) {
			dev_err(&pdev->dev, "request_irq %d failed\n", irq);
			goto err;
		}
		hw->xrp.host_irq_mode = true;
	} else {
		dev_info(&pdev->dev, "using polling mode on the host side\n");
	}

	if (ret == 0) {
	  ret = of_property_read_u32_array(pdev->dev.of_node, "dsp-reset",
		  			 hw->dsp_reset,
			  		 ARRAY_SIZE(hw->dsp_reset));
  }
	if (ret < 0) {
		dev_err(&pdev->dev, "Unspecified reset.\n");
		goto err;
	}

	if (ret == 0) {
	  ret = of_property_read_u32_array(pdev->dev.of_node, "dsp-runstall",
		  			 hw->dsp_runstall,
			  		 ARRAY_SIZE(hw->dsp_runstall));
  }
	if (ret < 0) {
		dev_err(&pdev->dev, "Unspecified runstall.\n");
		goto err;
	}
	ret = 0;
err:
	return ret;
}

static int init_dct(struct platform_device *pdev, struct xrp_hw_dct *hw)
{
	int ret;

	ret = init_hw_dct(pdev, hw, 2);
	if (ret < 0)
		return ret;

	return xrp_init_cma(pdev, &hw->xrp, &hw_ops, hw);
}

#ifdef CONFIG_OF
static const struct of_device_id xrp_hw_dct_match[] = {
	{
		.compatible = "cdns,xrp-hw-dct,cma",
		.data = init_dct,
	}, {},
};
MODULE_DEVICE_TABLE(of, xrp_hw_dct_match);
#endif

static int xrp_hw_dct_probe(struct platform_device *pdev)
{
	struct xrp_hw_dct *hw =
		devm_kzalloc(&pdev->dev, sizeof(*hw), GFP_KERNEL);
	const struct of_device_id *match;
	int (*init)(struct platform_device *pdev, struct xrp_hw_dct *hw);

	if (!hw)
		return -ENOMEM;

	match = of_match_device(of_match_ptr(xrp_hw_dct_match),
				&pdev->dev);
	if (!match)
		return -ENODEV;

	init = match->data;
	return init(pdev, hw);

}

static int xrp_hw_dct_remove(struct platform_device *pdev)
{
	return xrp_deinit(pdev);
}

static const struct dev_pm_ops xrp_hw_dct_pm_ops = {
	SET_RUNTIME_PM_OPS(xrp_runtime_suspend,
			   xrp_runtime_resume, NULL)
};

static struct platform_driver xrp_hw_dct_driver = {
	.probe   = xrp_hw_dct_probe,
	.remove  = xrp_hw_dct_remove,
	.driver  = {
		.name = DRIVER_NAME,
		.of_match_table = of_match_ptr(xrp_hw_dct_match),
		.pm = &xrp_hw_dct_pm_ops,
	},
};

module_platform_driver(xrp_hw_dct_driver);

MODULE_AUTHOR("Max Filippov");
MODULE_DESCRIPTION("XRP: low level device driver for Xtensa Remote Processing");
MODULE_LICENSE("Dual MIT/GPL");
