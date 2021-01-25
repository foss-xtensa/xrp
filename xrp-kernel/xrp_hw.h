/*
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

/*!
 * \file xrp_hw.h
 * \brief Interface between generic and HW-specific kernel drivers.
 */

#ifndef _XRP_HW
#define _XRP_HW

#include <linux/elf.h>
#include <linux/irqreturn.h>
#include <linux/platform_device.h>
#include <linux/types.h>

struct xvp;

/*!
 * Hardware-specific operation entry points.
 * Hardware-specific driver passes a pointer to this structure to xrp_init
 * at initialization time.
 */
struct xrp_hw_ops {
	/*!
	 * Enable power/clock, but keep the core stalled.
	 * \param hw_arg: opaque parameter passed to xrp_init at initialization
	 *                time
	 */
	int (*enable)(void *hw_arg);
	/*!
	 * Diable power/clock.
	 *
	 * \param hw_arg: opaque parameter passed to xrp_init at initialization
	 *                time
	 */
	void (*disable)(void *hw_arg);
	/*!
	 * Reset the core.
	 *
	 * \param hw_arg: opaque parameter passed to xrp_init at initialization
	 *                time
	 */
	void (*reset)(void *hw_arg);
	/*!
	 * Unstall the core.
	 *
	 * \param hw_arg: opaque parameter passed to xrp_init at initialization
	 *                time
	 */
	void (*release)(void *hw_arg);
	/*!
	 * Stall the core.
	 *
	 * \param hw_arg: opaque parameter passed to xrp_init at initialization
	 *                time
	 */
	void (*halt)(void *hw_arg);

	/*! Get HW-specific data to pass to the DSP on synchronization
	 *
	 * \param hw_arg: opaque parameter passed to xrp_init at initialization
	 *                time
	 * \param sz: return size of sync data here
	 * \return a buffer allocated with kmalloc that the caller will free
	 */
	void *(*get_hw_sync_data)(void *hw_arg, size_t *sz);

	/*!
	 * Send IRQ to the core.
	 *
	 * \param hw_arg: opaque parameter passed to xrp_init at initialization
	 *                time
	 */
	void (*send_irq)(void *hw_arg);

	/*!
	 * Check whether region of physical memory may be handled by
	 * dma_sync_* operations
	 *
	 * \param hw_arg: opaque parameter passed to xrp_init at initialization
	 *                time
	 */
	bool (*cacheable)(void *hw_arg, unsigned long pfn, unsigned long n_pages);
	/*!
	 * Synchronize region of memory for DSP access.
	 *
	 * \param hw_arg: opaque parameter passed to xrp_init at initialization
	 *                time
	 * \param flags: XRP_FLAG_{READ,WRITE,READWRITE}
	 */
	void (*dma_sync_for_device)(void *hw_arg,
				    void *vaddr, phys_addr_t paddr,
				    unsigned long sz, unsigned flags);
	/*!
	 * Synchronize region of memory for host access.
	 *
	 * \param hw_arg: opaque parameter passed to xrp_init at initialization
	 *                time
	 * \param flags: XRP_FLAG_{READ,WRITE,READWRITE}
	 */
	void (*dma_sync_for_cpu)(void *hw_arg,
				 void *vaddr, phys_addr_t paddr,
				 unsigned long sz, unsigned flags);

	/*!
	 * memcpy data/code to device-specific memory.
	 */
	void (*memcpy_tohw)(void __iomem *dst, const void *src, size_t sz);
	/*!
	 * memset device-specific memory.
	 */
	void (*memset_hw)(void __iomem *dst, int c, size_t sz);

	/*!
	 * Check DSP status.
	 *
	 * \param hw_arg: opaque parameter passed to xrp_init at initialization
	 *                time
	 * \return whether the core has crashed and needs to be restarted
	 */
	bool (*panic_check)(void *hw_arg);

	/*!
	 * Load firmware segment to the DSP.
	 *
	 * Load program segment described by phdr from the firmware image
	 * pointed to by image to the DSP.
	 * Provide this function when DSP memory is not directly mappable to
	 * the host address space and thus memcpy_tohw/memset_hw cannot be
	 * used.
	 *
	 * \param hw_arg: opaque parameter passed to xrp_init at initialization
	 *                time
	 * \param image: binary image of the firmware
	 * \param phdr: program header of a segment to be loaded
	 */
	long (*load_fw_segment)(void *hw_arg,
				const void *image,
				Elf32_Phdr *phdr);

	/*!
	 * Allocate host memory suitable for DMA to/from device.
	 *
	 * Provide this function when DSP memory is not directly mappable to
	 * the host address space.
	 *
	 * \param hw_arg: opaque parameter passed to xrp_init at initialization
	 *                time
	 * \param sz: amount of memory to allocate
	 * \return pointer to allocated memory or NULL in case of error
	 */
	void *(*alloc_host)(void *hw_arg, size_t sz);

	/*!
	 * Free host memory allocated with alloc_host.
	 *
	 * Provide this function when DSP memory is not directly mappable to
	 * the host address space.
	 *
	 * \param hw_arg: opaque parameter passed to xrp_init at initialization
	 *                time
	 * \param p: pointer to free
	 */
	void (*free_host)(void *hw_arg, void *p);

	/*!
	 * Copy block of size sz from the kernel address p to the DSP
	 * allocation at address paddr.
	 *
	 * Provide this function when DSP memory is not directly mappable to
	 * the host address space.
	 *
	 * \param hw_arg: opaque parameter passed to xrp_init at initialization
	 *                time
	 * \param p: kernel data pointer
	 * \param sz: size of data block
	 * \param paddr: address on the DSP side
	 * \return 0 if ok, negative error code if error
	 */
	long (*copy_to_alloc)(void *hw_arg,
			      const void *p, unsigned long sz,
			      phys_addr_t paddr);
	/*!
	 * Copy block of size sz to the kernel address p from the DSP
	 * allocation at address paddr.
	 *
	 * Provide this function when DSP memory is not directly mappable to
	 * the host address space.
	 *
	 * \param hw_arg: opaque parameter passed to xrp_init at initialization
	 *                time
	 * \param p: kernel data pointer
	 * \param sz: size of data block
	 * \param paddr: address on the DSP side
	 * \return 0 if ok, negative error code if error
	 */
	long (*copy_from_alloc)(void *hw_arg,
				void *p, unsigned long sz,
				phys_addr_t paddr);
	/*!
	 * Copy block of size sz from the user address vaddr to the DSP
	 * allocation at address paddr.
	 *
	 * Provide this function when DSP memory is not directly mappable to
	 * the host address space.
	 *
	 * \param hw_arg: opaque parameter passed to xrp_init at initialization
	 *                time
	 * \param vaddr: user data pointer
	 * \param sz: size of data block
	 * \param paddr: address on the DSP side
	 * \return 0 if ok, negative error code if error
	 */
	long (*copy_to_alloc_user)(void *hw_arg,
				   unsigned long vaddr, unsigned long sz,
				   phys_addr_t paddr);
	/*!
	 * Copy block of size sz to the user address vaddr from the DSP
	 * allocation at address paddr.
	 *
	 * Provide this function when DSP memory is not directly mappable to
	 * the host address space.
	 *
	 * \param hw_arg: opaque parameter passed to xrp_init at initialization
	 *                time
	 * \param vaddr: user data pointer
	 * \param sz: size of data block
	 * \param paddr: address on the DSP side
	 * \return 0 if ok, negative error code if error
	 */
	long (*copy_from_alloc_user)(void *hw_arg,
				     unsigned long vaddr, unsigned long sz,
				     phys_addr_t paddr);
};

enum xrp_init_flags {
	/*! Use interrupts in DSP->host communication */
	XRP_INIT_USE_HOST_IRQ = 0x1,

	/*! DSP memory cannot be mapped directly to host address space */
	XRP_INIT_NO_DIRECT_MAPPING = 0x2,
};

/*!
 * Initialize generic XRP kernel driver from cdns,xrp-compatible device
 * tree node.
 *
 * \param pdev: pointer to platform device associated with the XRP device
 *              instance
 * \param flags: initialization flags
 * \param hw: pointer to xrp_hw_ops structeure for this device
 * \param hw_arg: opaque pointer passed back to hw-specific functions
 * \return error code or pointer to struct xvp, use IS_ERR_VALUE and ERR_PTR
 */
long xrp_init(struct platform_device *pdev, enum xrp_init_flags flags,
	      const struct xrp_hw_ops *hw, void *hw_arg);

/*!
 * Initialize generic XRP kernel driver from cdns,xrp-compatible device
 * tree node. Set default address mapping.
 *
 * \param pdev: pointer to platform device associated with the XRP device
 *              instance
 * \param flags: initialization flags
 * \param hw: pointer to xrp_hw_ops structeure for this device
 * \param hw_arg: opaque pointer passed back to hw-specific functions
 * \return error code or pointer to struct xvp, use IS_ERR_VALUE and ERR_PTR
 */
long xrp_acpi_init_v0(struct platform_device *pdev, enum xrp_init_flags flags,
		      const struct xrp_hw_ops *hw, void *hw_arg);

/*!
 * Initialize generic XRP kernel driver from cdns,xrp,v1-compatible device
 * tree node.
 *
 * \param pdev: pointer to platform device associated with the XRP device
 *              instance
 * \param flags: initialization flags
 * \param hw: pointer to xrp_hw_ops structeure for this device
 * \param hw_arg: opaque pointer passed back to hw-specific functions
 * \return error code or pointer to struct xvp, use IS_ERR_VALUE and ERR_PTR
 */
long xrp_init_v1(struct platform_device *pdev, enum xrp_init_flags flags,
		 const struct xrp_hw_ops *hw, void *hw_arg);

/*!
 * Initialize generic XRP kernel driver from cdns,xrp,cma-compatible device
 * tree node.
 *
 * \param pdev: pointer to platform device associated with the XRP device
 *              instance
 * \param flags: initialization flags
 * \param hw: pointer to xrp_hw_ops structeure for this device
 * \param hw_arg: opaque pointer passed back to hw-specific functions
 * \return error code or pointer to struct xvp, use IS_ERR_VALUE and ERR_PTR
 */
long xrp_init_cma(struct platform_device *pdev, enum xrp_init_flags flags,
		  const struct xrp_hw_ops *hw, void *hw_arg);

/*!
 * Deinitialize generic XRP kernel driver.
 *
 * \param pdev: pointer to platform device associated with the XRP device
 *              instance
 * \return 0 on success, negative error code otherwise
 */
int xrp_deinit(struct platform_device *pdev);

/*!
 * Deinitialize generic XRP kernel driver.
 *
 * \param pdev: pointer to platform device associated with the XRP device
 *              instance
 * \param hw_arg: optional pointer to opaque pointer where generic XRP driver
 *                returns hw_arg that was associated with the pdev at xrp_init
 *                time
 * \return 0 on success, negative error code otherwise
 */
int xrp_deinit_hw(struct platform_device *pdev, void **hw_arg);

/*!
 * Notify generic XRP driver of possible IRQ from the DSP.
 *
 * \param irq: IRQ number
 * \param xvp: pointer to struct xvp returned from xrp_init* call
 * \return whether IRQ was recognized and handled
 */
irqreturn_t xrp_irq_handler(int irq, struct xvp *xvp);

/*!
 * Resume generic XRP operation of the device dev.
 *
 * \param dev: device which operation shall be resumed
 * \return 0 on success, negative error code otherwise
 */
int xrp_runtime_resume(struct device *dev);

/*!
 * Suspend generic XRP operation of the device dev.
 *
 * \param dev: device which operation shall be suspended
 * \return 0 on success, negative error code otherwise
 */
int xrp_runtime_suspend(struct device *dev);

#endif
