// SPDX-License-Identifier: GPL-2.0

#include <linux/irqflags.h>
#include <linux/spinlock.h>

__rust_helper void rust_helper_local_interrupt_disable(void)
{
	local_interrupt_disable();
}

__rust_helper void rust_helper_local_interrupt_enable(void)
{
	local_interrupt_enable();
}

__rust_helper unsigned long rust_helper_local_irq_save(void)
{
	unsigned long flags;

	local_irq_save(flags);
	return flags;
}

__rust_helper void rust_helper_local_irq_restore(unsigned long flags)
{
	local_irq_restore(flags);
}
