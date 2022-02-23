/*
 * Copyright (c) 2021 HWFLY
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <stdlib.h>

#include <bdk.h>

#include "config.h"
#include "gfx/tui.h"
#include <ianos/ianos.h>
#include <libs/compr/blz.h>
#include <libs/fatfs/ff.h>

#include "hwfly.h"

hekate_config h_cfg;
const volatile ipl_ver_meta_t __attribute__((section ("._ipl_version"))) ipl_ver = {
	.magic = BL_MAGIC,
	.version = (BL_VER_MJ + '0') | ((BL_VER_MN + '0') << 8) | ((BL_VER_HF + '0') << 16),
	.rsvd0 = 0,
	.rsvd1 = 0
};

volatile nyx_storage_t *nyx_str = (nyx_storage_t *)NYX_STORAGE_ADDR;

// This is a safe and unused DRAM region for our payloads.
#define RELOC_META_OFF      0x7C
#define PATCHED_RELOC_SZ    0x94
#define PATCHED_RELOC_STACK 0x40007000
#define PATCHED_RELOC_ENTRY 0x40010000
#define EXT_PAYLOAD_ADDR    0xC0000000
#define RCM_PAYLOAD_ADDR    (EXT_PAYLOAD_ADDR + ALIGN(PATCHED_RELOC_SZ, 0x10))
#define COREBOOT_END_ADDR   0xD0000000
#define COREBOOT_VER_OFF    0x41
#define CBFS_DRAM_EN_ADDR   0x4003e000
#define CBFS_DRAM_MAGIC     0x4452414D // "DRAM"

static void *coreboot_addr;

void reloc_patcher(u32 payload_dst, u32 payload_src, u32 payload_size)
{
	memcpy((u8 *)payload_src, (u8 *)IPL_LOAD_ADDR, PATCHED_RELOC_SZ);

	volatile reloc_meta_t *relocator = (reloc_meta_t *)(payload_src + RELOC_META_OFF);

	relocator->start = payload_dst - ALIGN(PATCHED_RELOC_SZ, 0x10);
	relocator->stack = PATCHED_RELOC_STACK;
	relocator->end   = payload_dst + payload_size;
	relocator->ep    = payload_dst;

	if (payload_size == 0x7000)
	{
		memcpy((u8 *)(payload_src + ALIGN(PATCHED_RELOC_SZ, 0x10)), coreboot_addr, 0x7000); //Bootblock
		*(vu32 *)CBFS_DRAM_EN_ADDR = CBFS_DRAM_MAGIC;
	}
}

int launch_payload(char *path, bool clear_screen)
{
	if (clear_screen)
		gfx_clear_grey(0x1B);
	gfx_con_setpos(0, 0);

	if (sd_mount())
	{
		FIL fp;
		if (f_open(&fp, path, FA_READ))
		{
			gfx_con.mute = false;
			EPRINTFARGS("Payload file is missing!\n(%s)", path);

			goto out;
		}

		// Read and copy the payload to our chosen address
		void *buf;
		u32 size = f_size(&fp);

		if (size < 0x30000)
			buf = (void *)RCM_PAYLOAD_ADDR;
		else
		{
			coreboot_addr = (void *)(COREBOOT_END_ADDR - size);
			buf = coreboot_addr;
			if (h_cfg.t210b01)
			{
				f_close(&fp);

				gfx_con.mute = false;
				EPRINTF("Coreboot not allowed on Mariko!");

				goto out;
			}
		}

		if (f_read(&fp, buf, size, NULL))
		{
			f_close(&fp);

			goto out;
		}

		f_close(&fp);

		sd_end();

		if (size < 0x30000)
		{
			reloc_patcher(PATCHED_RELOC_ENTRY, EXT_PAYLOAD_ADDR, ALIGN(size, 0x10));

			hw_reinit_workaround(false, byte_swap_32(*(u32 *)(buf + size - sizeof(u32))));
		}
		else
		{
			reloc_patcher(PATCHED_RELOC_ENTRY, EXT_PAYLOAD_ADDR, 0x7000);

			// Get coreboot seamless display magic.
			u32 magic = 0;
			char *magic_ptr = buf + COREBOOT_VER_OFF;
			memcpy(&magic, magic_ptr + strlen(magic_ptr) - 4, 4);
			hw_reinit_workaround(true, magic);
		}

		// Some cards (Sandisk U1), do not like a fast power cycle. Wait min 100ms.
		sdmmc_storage_init_wait_sd();

		void (*ext_payload_ptr)() = (void *)EXT_PAYLOAD_ADDR;

		// Launch our payload.
		(*ext_payload_ptr)();
	}

out:
	sd_end();

	return 1;
}

void hekate_launch()
{
	launch_payload("bootloader/update.bin", false);
}

#define EXCP_EN_ADDR    0x4003FFFC
#define EXCP_MAGIC      0x30505645  // EVP0
#define EXCP_TYPE_ADDR  0x4003FFF8
#define EXCP_TYPE_RESET 0x545352    // RST
#define EXCP_TYPE_UNDEF 0x464455    // UDF
#define EXCP_TYPE_PABRT 0x54424150  // PABT
#define EXCP_TYPE_DABRT 0x54424144  // DABT
#define EXCP_LR_ADDR    0x4003FFF4

#define PSTORE_LOG_OFFSET 0x180000
#define PSTORE_RAM_SIG    0x43474244 // DBGC.

typedef struct _pstore_buf {
	u32 sig;
	u32 start;
	u32 size;
} pstore_buf_t;

static void _show_errors()
{
	u32 *excp_enabled = (u32 *)EXCP_EN_ADDR;
	u32 *excp_type = (u32 *)EXCP_TYPE_ADDR;
	u32 *excp_lr = (u32 *)EXCP_LR_ADDR;
	u32 panic_status = hw_rst_status & 0xFFFFF;

	if (*excp_enabled == EXCP_MAGIC)
		h_cfg.errors |= ERR_EXCEPTION;

	if (PMC(APBDEV_PMC_SCRATCH37) == PMC_SCRATCH37_KERNEL_PANIC_MAGIC)
	{
		// Set error and clear flag.
		h_cfg.errors |= ERR_L4T_KERNEL;
		PMC(APBDEV_PMC_SCRATCH37) = 0;
	}

	if (hw_rst_reason == PMC_RST_STATUS_WATCHDOG && panic_status &&
		panic_status <= 0xFF && panic_status != 0x20 && panic_status != 0x21)
		h_cfg.errors |= ERR_PANIC_CODE;

	if (h_cfg.errors)
	{
		gfx_clear_grey(0x1B);
		gfx_con_setpos(0, 0);
		display_backlight_brightness(150, 1000);

		if (h_cfg.errors & ERR_SD_BOOT_EN)
		{
			WPRINTF("Failed to init or mount SD!\n");

			// Clear the module bits as to not cram the error screen.
			h_cfg.errors &= ~(ERR_LIBSYS_LP0 | ERR_LIBSYS_MTC);
		}

		if (h_cfg.errors & ERR_LIBSYS_LP0)
			WPRINTF("Missing LP0 (sleep) lib!\n");
		if (h_cfg.errors & ERR_LIBSYS_MTC)
			WPRINTF("Missing Minerva lib!\n");

		if (h_cfg.errors & (ERR_LIBSYS_LP0 | ERR_LIBSYS_MTC))
			WPRINTF("\nUpdate bootloader folder!\n\n");

		if (h_cfg.errors & ERR_EXCEPTION)
		{
			WPRINTFARGS("hekate exception occurred (LR %08X):\n", *excp_lr);
			switch (*excp_type)
			{
			case EXCP_TYPE_RESET:
				WPRINTF("RESET");
				break;
			case EXCP_TYPE_UNDEF:
				WPRINTF("UNDEF");
				break;
			case EXCP_TYPE_PABRT:
				WPRINTF("PABRT");
				break;
			case EXCP_TYPE_DABRT:
				WPRINTF("DABRT");
				break;
			}
			gfx_puts("\n");

			// Clear the exception.
			*excp_enabled = 0;
		}

		if (h_cfg.errors & ERR_L4T_KERNEL)
		{
			WPRINTF("Kernel panic occurred!\n");
			if (!(h_cfg.errors & ERR_SD_BOOT_EN))
			{
				if (!sd_save_to_file((void *)PSTORE_ADDR, PSTORE_SZ, "L4T_panic.bin"))
					WPRINTF("PSTORE saved to L4T_panic.bin");
				pstore_buf_t *buf = (pstore_buf_t *)(PSTORE_ADDR + PSTORE_LOG_OFFSET);
				if (buf->sig == PSTORE_RAM_SIG && buf->size < 0x80000)
				{
					u32 log_offset = PSTORE_ADDR + PSTORE_LOG_OFFSET + sizeof(pstore_buf_t);
					if (!sd_save_to_file((void *)log_offset, buf->size, "L4T_panic.txt"))
						WPRINTF("Log saved to L4T_panic.txt");
				}
			}
			gfx_puts("\n");
		}

		if (h_cfg.errors & ERR_PANIC_CODE)
		{
			u32 r = (hw_rst_status >> 20) & 0xF;
			u32 g = (hw_rst_status >> 24) & 0xF;
			u32 b = (hw_rst_status >> 28) & 0xF;
			r = (r << 16) | (r << 20);
			g = (g << 8) | (g << 12);
			b = (b << 0) | (b << 4);
			u32 color = r | g | b;

			WPRINTF("HOS panic occurred!\n");
			gfx_printf("Color: %k####%k, Code: %02X\n\n", color, 0xFFCCCCCC, panic_status);
		}

		WPRINTF("Press any key...");

		msleep(1000); // Guard against injection VOL+.
		btn_wait();
		msleep(500);  // Guard against force menu VOL-.
	}
}

void fw_update()
{
	gfx_clear_partial_grey(0x1B, 0, 1256);
	gfx_con_setpos(0, 0);

	hwfly_update_fw();

	gfx_printf("\n\nPress any key...\n");
	msleep(500);
	btn_wait();
}

void fw_dump()
{
	gfx_clear_partial_grey(0x1B, 0, 1256);
	gfx_con_setpos(0, 0);

	hwfly_dump_fw();

	gfx_printf("\n\nPress any key...\n");
	msleep(500);
	btn_wait();
}

void sdloader_update()
{
	gfx_clear_partial_grey(0x1B, 0, 1256);
	gfx_con_setpos(0, 0);

	gfx_printf("Reading sdloader.enc on sdcard\n");
	sd_mount();
	u32 payload_size;
	uint8_t *payload = sd_file_read("sdloader.enc", &payload_size);
	sd_end();

	if (!payload)
	{
		gfx_printf("sdloader.enc not found!\n");
		goto out;
	}

	payload_size = ALIGN(payload_size, 512);
	emmc_initialize(false);
	sdmmc_storage_set_mmc_partition(&emmc_storage, EMMC_BOOT0);
	sdmmc_storage_write(&emmc_storage, 0x3F0000 / 512, payload_size / 512, payload);
	sdmmc_storage_end(&emmc_storage);
	gfx_printf("Flashed!\n\n");

out:
	gfx_printf("Press any key\n");
	msleep(500);
	btn_wait();
}

void sdloader_dump()
{
	gfx_clear_partial_grey(0x1B, 0, 1256);
	gfx_con_setpos(0, 0);

	int payload_size = 64 * 1024;
	void *payload = calloc(payload_size, 1);

	gfx_printf("Reading loader from BOOT0\n");
	emmc_initialize(false);
	sdmmc_storage_set_mmc_partition(&emmc_storage, EMMC_BOOT0);
	sdmmc_storage_read(&emmc_storage, 0x3F0000 / 512, payload_size / 512, payload);
	sdmmc_storage_end(&emmc_storage);

	gfx_printf("Writing to dumped_sdloader.enc.. ");
	sd_mount();
	sd_save_to_file(payload, payload_size, "dumped_sdloader.enc");
	sd_end();
	gfx_printf("Done\n\n");

	free(payload);

	gfx_printf("Press any key\n");
	msleep(500);
	btn_wait();
}

void train_data_show()
{
	gfx_clear_partial_grey(0x1B, 0, 1256);
	gfx_con_setpos(0, 0);

	gfx_printf("Reading train data..\n");
	uint32_t load_result;
	config_t train_data;
	if (!hwfly_get_train_data(&load_result, &train_data))
	{
		gfx_clear_partial_grey(0x1B, 0, 1256);
		gfx_con_setpos(0, 0);

		gfx_printf("Stored train data report:\n");

		bool valid = load_result == 0x900D0007 &&
					 train_data.magic == CONFIG_MAGIC &&
					 train_data.count <= 32;

		gfx_printf("Status: %k%s%k, configs count: %d\n\n", 
				   valid ? 0xFF00FF00 : 0xFFFF0000, 
				   valid ? "valid" : "invalid", 0xFFC0C0C0, 
				   valid ? train_data.count : -1);

		if (valid)
		{
			gfx_printf("  #   Used   Offset   Width\n");
			for (int i = 0; i < train_data.count; ++i)
			{
				gfx_printf("%3d%7d%9d%8d\n", i + 1, train_data.timings[i].success, 
						   train_data.timings[i].offset, train_data.timings[i].width);
			}
		}
	}
	else
	{
		EPRINTF("Could not obtain train data from modchip\n");
	}
	gfx_printf("\nPress any key\n");

	msleep(500);
	btn_wait();
}

void train_data_backup()
{
	gfx_clear_partial_grey(0x1B, 0, 1256);
	gfx_con_setpos(0, 0);

	gfx_printf("Reading train data.. ");
	uint32_t load_result;
	config_t train_data;
	if (!hwfly_get_train_data(&load_result, &train_data))
	{
		gfx_printf("Done\n");
		if (load_result == 0x900D0007 &&
			train_data.magic == CONFIG_MAGIC &&
			train_data.count <= 32)
		{
			gfx_printf("Writing train_data.bin.. ");
			sd_mount();
			sd_save_to_file(&train_data, sizeof(config_t), "train_data.bin");
			sd_end();
			gfx_printf("Done\n\n");
		}
		else
		{
			EPRINTF("\nInvalid train data received. Backup failed.\n");	
		}
	}
	else
	{
		EPRINTF("Could not obtain train data from modchip\n");
	}
	gfx_printf("\nPress any key\n");

	msleep(500);
	btn_wait();
}

void train_data_restore()
{
    gfx_clear_partial_grey(0x1B, 0, 1256);
    gfx_con_setpos(0, 0);

    gfx_printf("Reading train_data.bin from SD\n");
	sd_mount();
	u32 train_data_size;
	uint8_t *train_data = sd_file_read("train_data.bin", &train_data_size);
	sd_end();

	if (!train_data)
	{
		gfx_printf("train_data.bin not found!\n");
		goto out;
	}
	else if (train_data_size != sizeof(config_t))
	{
		EPRINTFARGS("Train data size %d bytes incorrect, expected %d bytes", train_data_size, sizeof(config_t));
	}
	else if (!hwfly_set_train_data((config_t *)train_data))
		gfx_printf("Train data written to modchip\n");
	else
		EPRINTF("Failed to write train data to modchip");

	free(train_data);

	out:
		gfx_printf("Press any key\n");
	msleep(500);
	btn_wait();
}

void train_data_reset()
{
	gfx_clear_partial_grey(0x1B, 0, 1256);
	gfx_con_setpos(0, 0);

	gfx_printf("Sending Reset Train Data command\n");

	if (!hwfly_reset_train_data())
	{
		gfx_printf("Train data reset. Next boot will retrain.\n");
	}
	else
	{
		EPRINTF("Train data reset failed.\n");
	}
	gfx_printf("Press any key...\n");

	msleep(500);
	btn_wait();
}

void session_info()
{
	gfx_clear_partial_grey(0x1B, 0, 1256);
	gfx_con_setpos(0, 0);

	uint8_t fmt;
	session_info_t si;
	if (!hwfly_session_info(&fmt, &si))
	{
		if (fmt == SESSION_INFO_FORMAT_VER)
		{
			const char* board_type;
			if (si.fpga_type == 0x2E49564D && si.board_id == BOARD_ID_CORE) 
				board_type = "HWFLY CORE";
			else if (si.fpga_type == 0x2E49564D && si.board_id == BOARD_ID_LITE) 
				board_type = "HWFLY OLED";
			else if (si.board_id == BOARD_ID_CORE) 
				board_type = "SX-CORE";
			else if (si.board_id == BOARD_ID_LITE) 
				board_type = "SX-LITE";
			else 
				board_type = "Unknown";

			const char* device_type;
			if (si.device_type == DEVICE_TYPE_ERISTA)
				device_type = "Erista";
			else if (si.device_type == DEVICE_TYPE_MARIKO)
				device_type = "Mariko";
			else if (si.fpga_type == 0x2E49564D && si.board_id == BOARD_ID_LITE && si.device_type == DEVICE_TYPE_LITE)
				device_type = "OLED";
			else if (si.device_type == DEVICE_TYPE_LITE)
				device_type = "Lite";
			else
				device_type = "Unknown";
				
			gfx_printf("--- Info for last glitch session ---\n\n");
			gfx_printf("%kBoard ID:%k %s\n", 0xFFC0C0C0, 0xFF808080, board_type);
			gfx_printf("%kDevice type:%k %s\n", 0xFFC0C0C0, 0xFF808080, device_type);
			gfx_printf("\n");
			gfx_printf("%kAttempts used:%k %d\n", 0xFFC0C0C0, 0xFF808080, si.glitch_attempt);
			gfx_printf("\n");
			gfx_printf("%kGlitch params:\n", 0xFFC0C0C0);
			gfx_printf("%k Offset:%k %d\n", 0xFFC0C0C0, 0xFF808080, si.glitch_cfg.offset);
			gfx_printf("%k Width:%k %d\n", 0xFFC0C0C0, 0xFF808080, si.glitch_cfg.width);
			gfx_printf("%k Sub-cycle:%k %d\n", 0xFFC0C0C0, 0xFF808080, si.glitch_cfg.subcycle_delay);
			gfx_printf("\n");
			gfx_printf("%kTiming:\n", 0xFFC0C0C0);
			gfx_printf("%k Power goal reached:%k %dus\n", 0xFFC0C0C0, 0xFF808080, si.power_threshold_reached_us);
			gfx_printf("%k ADC goal reached:  %k %dus\n", 0xFFC0C0C0, 0xFF808080, si.adc_goal_reached_us);
			gfx_printf("%k Glitch completed:  %k %dus\n", 0xFFC0C0C0, 0xFF808080, si.glitch_complete_us);
			gfx_printf("%k Glitch confirmed:  %k %dus (%d reads)\n", 0xFFC0C0C0, 0xFF808080, si.glitch_confirm_us, si.flag_reads_before_glitch_confirmed);
			gfx_printf("%k Total time:        %k %dus\n", 0xFFC0C0C0, 0xFF808080, si.total_time_us);
			gfx_printf("\n");
			gfx_printf("%kStartup ADC:%k %d\n", 0xFFC0C0C0, 0xFF808080, si.startup_adc_value);
			gfx_printf("%kDevice reset:%k %s\n", 0xFFC0C0C0, 0xFF808080, si.was_the_device_reset ? "yes" : "no");
			gfx_printf("%kPayload flashed:%k %s\n", 0xFFC0C0C0, 0xFF808080, si.payload_flashed ? "yes" : "no");
		}
		else
			EPRINTF("Session info received in unknown format.\n");
	}
	else
		EPRINTF("Could not retrieve session info.\n");

	gfx_printf("\nPress any key...\n");

	msleep(500);
	btn_wait();
}

void deep_sleep()
{
	gfx_clear_partial_grey(0x1B, 0, 1256);
	gfx_con_setpos(0, 0);

	gfx_printf("Sending Deep Sleep command\n");
	hwfly_enter_deep_sleep();
	gfx_printf("Modchip is now in Deep Sleep\n");

	gfx_printf("\nPress any key...\n");

	msleep(500);
	btn_wait();
}

power_state_t STATE_POWER_OFF           = POWER_OFF_RESET;

ment_t ment_top[] = {
	MDEF_CAPTION("--- Firmware ------", 0xFFDAFF7F),
	MDEF_HANDLER("Update", fw_update),
	MDEF_HANDLER("Backup", fw_dump),
	MDEF_CAPTION("--- SD Loader -----", 0xFFDAFF7F),
	MDEF_HANDLER("Update", sdloader_update),
	MDEF_HANDLER("Backup", sdloader_dump),
	MDEF_CAPTION("--- Train data ----", 0xFFDAFF7F),
	MDEF_HANDLER("Show stored data", train_data_show),
	MDEF_HANDLER("Backup", train_data_backup),
	MDEF_HANDLER("Restore", train_data_restore),
	MDEF_HANDLER("Reset", train_data_reset),
	MDEF_CAPTION("--- Misc. ---------", 0xFFDAFF7F),
	MDEF_HANDLER("Glitch Session Info", session_info),
	MDEF_HANDLER("Enter Deep Sleep", deep_sleep),
	MDEF_CAPTION("-------------------", 0xFFDAFF7F),
	MDEF_HANDLER("Back to hekate", hekate_launch),
	MDEF_HANDLER_EX("Power off", &STATE_POWER_OFF, power_set_state_ex),
	MDEF_END()
};

menu_t menu_top = { ment_top, "HWFLY Toolbox v1.0.0", 0, 0 };

extern void pivot_stack(u32 stack_top);

void ipl_main()
{
	// Do initial HW configuration. This is compatible with consecutive reruns without a reset.
	hw_init();

	// Pivot the stack so we have enough space.
	pivot_stack(IPL_STACK_TOP);

	// Tegra/Horizon configuration goes to 0x80000000+, package2 goes to 0xA9800000, we place our heap in between.
	heap_init(IPL_HEAP_START);

	// Set bootloader's default configuration.
	set_default_configuration();

	// Initialize display.
	display_init();

	// Mount SD Card.
	h_cfg.errors |= !sd_mount() ? ERR_SD_BOOT_EN : 0;

	// Train DRAM and switch to max frequency.
	if (minerva_init()) //!TODO: Add Tegra210B01 support to minerva.
		h_cfg.errors |= ERR_LIBSYS_MTC;

	// Initialize display window, backlight and gfx console.
	u32 *fb = display_init_framebuffer_pitch();
	gfx_init_ctxt(fb, 720, 1280, 720);
	gfx_con_init();

	display_backlight_pwm_init();
	//display_backlight_brightness(h_cfg.backlight, 1000);

	// Overclock BPMP.
	bpmp_clk_rate_set(h_cfg.t210b01 ? BPMP_CLK_DEFAULT_BOOST : BPMP_CLK_LOWER_BOOST);

	// Show exceptions, HOS errors, library errors and L4T kernel panics.
	_show_errors();

	// Failed to launch Nyx, unmount SD Card.
	sd_end();

	// Set ram to a freq that doesn't need periodic training.
	minerva_change_freq(FREQ_800);

	while (true)
		tui_do_menu(&menu_top);

	// Halt BPMP if we managed to get out of execution.
	while (true)
		bpmp_halt();
}
