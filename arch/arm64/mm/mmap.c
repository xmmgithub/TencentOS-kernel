// SPDX-License-Identifier: GPL-2.0-only
/*
 * Based on arch/arm/mm/mmap.c
 *
 * Copyright (C) 2012 ARM Ltd.
 */

#include <linux/elf.h>
#include <linux/fs.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/export.h>
#include <linux/shm.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/io.h>
#include <linux/personality.h>
#include <linux/random.h>
#include <linux/security.h>
#include <linux/hugetlb.h>

#include <asm/cputype.h>

#ifdef CONFIG_EXAGEAR_BT
/* Definitions for Exagear's guest mmap area */
#define EXAGEAR_TASK_UNMAPPED_BASE        PAGE_ALIGN(TASK_SIZE_32 / 4)
#endif

/*
 * You really shouldn't be using read() or write() on /dev/mem.  This might go
 * away in the future.
 */
int valid_phys_addr_range(phys_addr_t addr, size_t size)
{
	/*
	 * Check whether addr is covered by a memory region without the
	 * MEMBLOCK_NOMAP attribute, and whether that region covers the
	 * entire range. In theory, this could lead to false negatives
	 * if the range is covered by distinct but adjacent memory regions
	 * that only differ in other attributes. However, few of such
	 * attributes have been defined, and it is debatable whether it
	 * follows that /dev/mem read() calls should be able traverse
	 * such boundaries.
	 */
	return memblock_is_region_memory(addr, size) &&
	       memblock_is_map_memory(addr);
}

/*
 * Do not allow /dev/mem mappings beyond the supported physical range.
 */
int valid_mmap_phys_addr_range(unsigned long pfn, size_t size)
{
	return !(((pfn << PAGE_SHIFT) + size) & ~PHYS_MASK);
}

#ifdef CONFIG_STRICT_DEVMEM

#include <linux/ioport.h>

/*
 * devmem_is_allowed() checks to see if /dev/mem access to a certain address
 * is valid. The argument is a physical page number.  We mimic x86 here by
 * disallowing access to system RAM as well as device-exclusive MMIO regions.
 * This effectively disable read()/write() on /dev/mem.
 */
int devmem_is_allowed(unsigned long pfn)
{
	if (iomem_is_exclusive(pfn << PAGE_SHIFT))
		return 0;
	if (!page_is_ram(pfn))
		return 1;
	return 0;
}

#endif

#ifdef CONFIG_EXAGEAR_BT

/* Get an address range which is currently unmapped.
 * For shmat() with addr=0.
 *
 * Ugly calling convention alert:
 * Return value with the low bits set means error value,
 * ie
 *	if (ret & ~PAGE_MASK)
 *		error = ret;
 *
 * This function "knows" that -ENOMEM has the bits set.
 */
unsigned long
arch_get_unmapped_area(struct file *filp, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma, *prev;
	struct vm_unmapped_area_info info;
	bool bad_addr = false;

	if (len > TASK_SIZE - mmap_min_addr)
		return -ENOMEM;

	/*
	 * Ensure that translated processes do not allocate the last
	 * page of the 32-bit address space, or anything above it.
	 */
	if (is_exagear_compat_task())
		bad_addr = addr + len > TASK_SIZE_32 - PAGE_SIZE;

	if (flags & MAP_FIXED)
		return bad_addr ? -ENOMEM : addr;

	if (addr && !bad_addr) {
		addr = PAGE_ALIGN(addr);
		vma = find_vma_prev(mm, addr, &prev);
		if (TASK_SIZE - len >= addr && addr >= mmap_min_addr &&
		    (!vma || addr + len <= vm_start_gap(vma)) &&
		    (!prev || addr >= vm_end_gap(prev)))
			return addr;
	}

	info.flags = 0;
	info.length = len;
	if (is_exagear_compat_task()) {
		info.low_limit = mm->context.exagear_mmap_base;
		info.high_limit = TASK_SIZE_32 - PAGE_SIZE;
	} else {
		info.low_limit = mm->mmap_base;
		info.high_limit = TASK_SIZE;
	}
	info.align_mask = 0;
	return vm_unmapped_area(&info);
}

/*
 * This mmap-allocator allocates new areas top-down from below the
 * stack's low limit (the base):
 */
unsigned long
arch_get_unmapped_area_topdown(struct file *filp, const unsigned long addr0,
			  const unsigned long len, const unsigned long pgoff,
			  const unsigned long flags)
{
	struct vm_area_struct *vma, *prev;
	struct mm_struct *mm = current->mm;
	unsigned long addr = addr0;
	struct vm_unmapped_area_info info;
	bool bad_addr = false;

	/* requested length too big for entire address space */
	if (len > TASK_SIZE - mmap_min_addr)
		return -ENOMEM;

	/*
	 * Ensure that translated processes do not allocate the last
	 * page of the 32-bit address space, or anything above it.
	 */
	if (is_exagear_compat_task())
		bad_addr = addr + len > TASK_SIZE_32 - PAGE_SIZE;

	if (flags & MAP_FIXED)
		return bad_addr ? -ENOMEM : addr;

	/* requesting a specific address */
	if (addr && !bad_addr) {
		addr = PAGE_ALIGN(addr);
		vma = find_vma_prev(mm, addr, &prev);
		if (TASK_SIZE - len >= addr && addr >= mmap_min_addr &&
				(!vma || addr + len <= vm_start_gap(vma)) &&
				(!prev || addr >= vm_end_gap(prev)))
			return addr;
	}

	info.flags = VM_UNMAPPED_AREA_TOPDOWN;
	info.length = len;
	info.low_limit = max(PAGE_SIZE, mmap_min_addr);
	if (is_exagear_compat_task())
		info.high_limit = mm->context.exagear_mmap_base;
	else
		info.high_limit = mm->mmap_base;
	info.align_mask = 0;
	addr = vm_unmapped_area(&info);

	/*
	 * A failed mmap() very likely causes application failure,
	 * so fall back to the bottom-up function here. This scenario
	 * can happen with large stack limits and large mmap()
	 * allocations.
	 */
	if (offset_in_page(addr)) {
		VM_BUG_ON(addr != -ENOMEM);
		info.flags = 0;
		if (is_exagear_compat_task()) {
			info.low_limit = EXAGEAR_TASK_UNMAPPED_BASE;
			info.high_limit = TASK_SIZE_32 - PAGE_SIZE;
		} else {
			info.low_limit = TASK_UNMAPPED_BASE;
			info.high_limit = TASK_SIZE;
		}
		addr = vm_unmapped_area(&info);
	}

	return addr;
}

unsigned long
hugetlb_get_unmapped_area(struct file *file, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct hstate *h = hstate_file(file);
	struct vm_unmapped_area_info info;
	bool bad_addr = false;

	if (len & ~huge_page_mask(h))
		return -EINVAL;
	if (len > TASK_SIZE)
		return -ENOMEM;

	/*
	 * Ensure that translated processes do not allocate the last
	 * page of the 32-bit address space, or anything above it.
	 */
	if (is_exagear_compat_task())
		bad_addr = addr + len > TASK_SIZE_32 - PAGE_SIZE;

	if (flags & MAP_FIXED) {
		if (prepare_hugepage_range(file, addr, len))
			return -EINVAL;
		return bad_addr ? -ENOMEM : addr;
	}

	if (addr && !bad_addr) {
		addr = ALIGN(addr, huge_page_size(h));
		vma = find_vma(mm, addr);
		if (TASK_SIZE - len >= addr &&
		    (!vma || addr + len <= vm_start_gap(vma)))
			return addr;
	}

	info.flags = 0;
	info.length = len;
	if (is_exagear_compat_task()) {
		info.low_limit = EXAGEAR_TASK_UNMAPPED_BASE;
		info.high_limit = TASK_SIZE_32 - PAGE_SIZE;
	} else {
		info.low_limit = TASK_UNMAPPED_BASE;
		info.high_limit = TASK_SIZE;
	}
	info.align_mask = PAGE_MASK & ~huge_page_mask(h);
	info.align_offset = 0;
	return vm_unmapped_area(&info);
}

#endif
