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
#include "gfx/tui.h"
#include "hwfly.h"

#define DFU_XFER_BYTES 64
#define DFU_FW_OFFSET  0x3000
#define DFU_FLASH_SIZE 0x20000

enum DFU_ERRORS
{
	ERROR_SUCCESS                = 0x70000000,
	ERROR_INVALID_PACKAGE_LENGTH = 0x40000000,
	ERROR_INVALID_OFFSET,       // 0x40000001
	ERROR_INVALID_LENGTH,       // 0x40000002
	ERROR_ERASE_FAILED,         // 0x40000003
	ERROR_FLASH_FAILED,         // 0x40000004
	ERROR_FAILED_TO_UPDATE_OB,  // 0x40000005

	ERROR_UNIMPLEMENTED          = 0x50000000,

	ERROR_XFER_TIMEOUT           = 0xFFFFFFFF
};

enum DFU_COMMANDS
{
	DFU_PING         = 0xA0F0,
	DFU_SET_OFFSET, // 0xA0F1
	DFU_READ_FLASH, // 0xA0F2
	DFU_READ_OB,    // 0xA0F3
	DFU_SET_OB,     // 0xA0F4
};

enum FW_COMMANDS
{
	FW_GET_VER = 0x44,
	FW_DEEP_SLEEP = 0x55,
	FW_GET_TRAIN_DATA = 0x66,
	FW_SET_TRAIN_DATA = 0x77,
	FW_RESET_TRAIN_DATA = 0x88,
	FW_SESSION_INFO = 0x99,
	FW_ENTER_DFU = 0xAA
};

#define TRAIN_DATA_RESET_MAGIC 0x14CCB847
#define TRAIN_DATA_SET_MAGIC 0xC88350AE

typedef struct
{
	uint8_t len;
	uint16_t cmd;
	uint32_t arg;
	uint32_t arg2;
} __attribute__((packed)) dfu_cmd_t;

typedef struct
{
	uint8_t resp;
	uint32_t result;
} __attribute__((packed)) dfu_resp_t;

typedef struct
{
	uint8_t cmd; // FW_COMMAND
	union
	{
		struct
		{
			uint16_t cmd;
			uint32_t arg;
			uint32_t arg2;
		} __attribute__((packed)) dfu;

		struct
		{
			uint32_t magic;
			config_t cfg;
		} train_data;
	};
} __attribute__((packed)) sdio_req_t;

typedef struct
{
	uint8_t cmd; // ~FW_COMMAND
	union
	{
		uint32_t dfu_result;
		uint32_t fw_info;
		uint32_t train_data_ack;
		struct
		{
			uint32_t magic : 24;
			uint32_t format : 8;
			session_info_t data;
		} session_info;
		struct
		{
			uint32_t load_result;
			config_t cfg;
		} train_data;
	};
} __attribute__((packed)) sdio_resp_t;

uint8_t *MMC_BUFFER = (uint8_t *)SDXC_BUF_ALIGNED;

// HWFLY FPGA SDMMC
static void sdmmc_hwfly_recv(sdmmc_t *sdmmc, uint8_t *buf)
{
	sdmmc_cmd_t cmdbuf;
	sdmmc_req_t reqbuf;

	sdmmc_init_cmd(&cmdbuf, MMC_GO_IDLE_STATE, 0xAA5458BB, SDMMC_RSP_TYPE_1, 0);

	reqbuf.buf = buf;
	reqbuf.blksize = 512;
	reqbuf.num_sectors = 1;
	reqbuf.is_write = 0;
	reqbuf.is_multi_block = 0;
	reqbuf.is_auto_stop_trn = 0;

	sdmmc_execute_cmd(sdmmc, &cmdbuf, &reqbuf, 0);
}

static void sdmmc_hwfly_send(sdmmc_t *sdmmc, uint8_t *buf)
{
	sdmmc_cmd_t cmdbuf;
	sdmmc_req_t reqbuf;

	sdmmc_init_cmd(&cmdbuf, MMC_GO_IDLE_STATE, 0xAA5458BA, SDMMC_RSP_TYPE_1, 0);

	reqbuf.buf = buf;
	reqbuf.blksize = 512;
	reqbuf.num_sectors = 1;
	reqbuf.is_write = 1;
	reqbuf.is_multi_block = 0;
	reqbuf.is_auto_stop_trn = 0;

	sdmmc_execute_cmd(sdmmc, &cmdbuf, &reqbuf, 0);
}

// HWFLY xfer
static uint32_t hwfly_xfer_start(uint32_t timeout_s)
{
	uint32_t timeout = get_tmr_ms() + timeout_s * 1000;
	uint8_t b0inv = (uint8_t)~MMC_BUFFER[0];

	sdmmc_hwfly_send(&emmc_sdmmc, MMC_BUFFER);
	do
	{
		msleep(10);
		sdmmc_hwfly_recv(&emmc_sdmmc, MMC_BUFFER);

		if (get_tmr_ms() > timeout)
			return ERROR_XFER_TIMEOUT;
	} while (MMC_BUFFER[0] != b0inv);

	return 0;
}

static uint32_t hwfly_dfu_xfer_start(uint8_t len, uint32_t timeout_s)
{
	dfu_cmd_t *mcmd = (dfu_cmd_t *)MMC_BUFFER;
	mcmd->len = len;

	dfu_resp_t *mresp = (dfu_resp_t *)MMC_BUFFER;
	uint32_t xfer_res = hwfly_xfer_start(timeout_s);

	if (xfer_res)
		return xfer_res;
	else
		return mresp->result != ERROR_SUCCESS;
}

// HWFLY DFU
static void hwfly_enter_dfu()
{
	sdio_req_t *mreq = (sdio_req_t *)MMC_BUFFER;
	mreq->cmd = FW_ENTER_DFU;
	// no ack
	sdmmc_hwfly_send(&emmc_sdmmc, MMC_BUFFER);
}

static void hwfly_exit_dfu()
{
	hwfly_dfu_xfer_start(1, 10);
}

static uint32_t hwfly_dfu_ping()
{
	dfu_cmd_t *mcomms = (dfu_cmd_t *)MMC_BUFFER;

	mcomms->cmd = DFU_PING;
	if (!hwfly_dfu_xfer_start(sizeof(mcomms->cmd), 5))
		return 0;

	return 1;
}

static int hwfly_dfu_set_flash_addr(uint32_t offset)
{
	dfu_cmd_t *mcomms = (dfu_cmd_t *)MMC_BUFFER;

	if (hwfly_dfu_ping())
		return 1;

	mcomms->cmd = DFU_SET_OFFSET;
	mcomms->arg = offset;
	if (!hwfly_dfu_xfer_start(sizeof(mcomms->cmd) + sizeof(mcomms->arg), 10))
		return 0;

	return 2;
}

static int hwfly_dfu_read_flash(uint32_t offset, void *buffer)
{
	dfu_cmd_t *mcomms = (dfu_cmd_t *)MMC_BUFFER;
	uint8_t len = sizeof(mcomms->cmd) + sizeof(mcomms->arg) * 2;

	mcomms->len = len;
	mcomms->cmd = DFU_READ_FLASH;
	mcomms->arg = offset;
	mcomms->arg2 = DFU_XFER_BYTES;

	uint32_t timeout = get_tmr_ms() + 10000;
	sdmmc_hwfly_send(&emmc_sdmmc, MMC_BUFFER);

	do
	{
		// receive data
		msleep(10);
		sdmmc_hwfly_recv(&emmc_sdmmc, MMC_BUFFER);

		if (get_tmr_ms() > timeout)
			return 1;
	} while (MMC_BUFFER[0] != (uint8_t) ~len);

	memcpy(buffer, &MMC_BUFFER[1], DFU_XFER_BYTES);

	return 0;
}

// HWFLY Firmware
static uint32_t hwfly_get_fw_version(uint32_t *version)
{
	sdio_req_t *mreq = (sdio_req_t *)MMC_BUFFER;
	mreq->cmd = FW_GET_VER;

	sdio_resp_t *mresp = (sdio_resp_t *)MMC_BUFFER;
	uint32_t xfer_res = hwfly_xfer_start(2);
	if (!xfer_res)
		*version = mresp->dfu_result;

	return xfer_res;
}

static uint32_t hwfly_session_info_get(uint8_t *format, session_info_t* si)
{
	sdio_req_t *mreq = (sdio_req_t *)MMC_BUFFER;
	mreq->cmd = FW_SESSION_INFO;

	sdio_resp_t *mresp = (sdio_resp_t *)MMC_BUFFER;
	uint32_t xfer_res = hwfly_xfer_start(2);
	if (!xfer_res)
	{
		if (mresp->session_info.magic == SESSION_INFO_MAGIC)
		{
			*format = mresp->session_info.format;
			*si = mresp->session_info.data;
			return 0;
		}
		else
			return 1; // invalid magic
	}
	else
		return xfer_res;
}

static uint32_t hwfly_train_data_get(uint32_t *load_result, config_t *cfg)
{
	sdio_req_t *mreq = (sdio_req_t *)MMC_BUFFER;
	mreq->cmd = FW_GET_TRAIN_DATA;

	sdio_resp_t *mresp = (sdio_resp_t *)MMC_BUFFER;
	uint32_t xfer_res = hwfly_xfer_start(2);
	if (!xfer_res)
	{
		*load_result = mresp->train_data.load_result;
		*cfg = mresp->train_data.cfg;
	}

	return xfer_res;
}
static uint32_t hwfly_train_data_set(config_t *cfg)
{
	sdio_req_t *mreq = (sdio_req_t *)MMC_BUFFER;
	mreq->cmd = FW_SET_TRAIN_DATA;

	mreq->train_data.magic = TRAIN_DATA_SET_MAGIC;
	mreq->train_data.cfg = *cfg;

	sdio_resp_t *mresp = (sdio_resp_t *)MMC_BUFFER;
	uint32_t xfer_res = hwfly_xfer_start(2);

	return xfer_res ? xfer_res : mresp->train_data_ack != 0xA11600D;
}

static uint32_t hwfly_train_data_reset()
{
	sdio_req_t *mreq = (sdio_req_t *)MMC_BUFFER;
	mreq->cmd = FW_RESET_TRAIN_DATA;
	mreq->train_data.magic = TRAIN_DATA_RESET_MAGIC;

	sdio_resp_t *mresp = (sdio_resp_t *)MMC_BUFFER;
	uint32_t xfer_res = hwfly_xfer_start(2);

	return xfer_res ? xfer_res : mresp->train_data_ack != 0xA11600D;
}

static void hwfly_enable_deep_sleep()
{
	sdio_req_t *mreq = (sdio_req_t *)MMC_BUFFER;
	mreq->cmd = FW_DEEP_SLEEP;
	hwfly_xfer_start(2);
}

// HWFLY features
uint32_t fw_version = 0xFFFFFFFF;
void hwfly_update_fw()
{
	FIL fp;
	uint32_t new_version = 0;

	gfx_printf("Getting HWFLY FW version...\n");

	sdmmc_init(&emmc_sdmmc, SDMMC_4, SDMMC_POWER_1_8, SDMMC_BUS_WIDTH_1, SDHCI_TIMING_MMC_ID, SDMMC_POWER_SAVE_DISABLE);
	sd_mount();
	bool force_update = f_stat(".force_update", NULL) == FR_OK;

	uint32_t current_version;
	if (hwfly_get_fw_version(&current_version) == ERROR_XFER_TIMEOUT)
	{
		if (!hwfly_dfu_ping())
		{
			if (fw_version != 0xFFFFFFFF)
			{
				// restore version from previous session
				current_version = fw_version;
				gfx_printf("Already in DFU mode!\n");
			}
			else if (!force_update)
			{
				EPRINTF("In DFU mode and no version info!\nAborting...\n");
				goto out;
			}
		}
		else
		{
			EPRINTF("Couldn't communicate with HWFLY!\n");
			goto out;
		}
	}

	// save version
	fw_version = current_version;

	gfx_printf("Current FW Ver: %d\nForce update: %d\n\n", current_version, force_update);

	u32 size = 0;
	uint8_t *firmware = sd_file_read("firmware.bin", &size);

	if (!firmware) {
		EPRINTF("firmware.bin not found!\n");
		goto out;
	}

	// open update
	if (firmware)
	{
		// read fw version
		new_version = *(uint32_t *)(firmware + 0x150);

		// check if update is newer or forced and <= 128KB
		if ((!force_update && (new_version <= current_version)) || size > 0x20000)
		{
			if (size > 0x20000)
			{
				EPRINTF("Firmware in SD too big!");
			}
			else
			{
				EPRINTF("Firmware in SD not newer!");
			}

			f_close(&fp);
			goto out;
		}

		if (force_update)
			gfx_printf("Forced update to version %d.\nPress Power to update or VOL to exit..\n", new_version);
		else
			gfx_printf("New version %d found.\nPress Power to update or VOL to exit..\n", new_version);

		msleep(500);
		uint32_t btn = btn_wait();
		if (btn & (BTN_VOL_UP | BTN_VOL_DOWN))
		{
			f_close(&fp);
			goto out;
		}

		gfx_printf("\nEntering DFU mode..");
		// set HWFLY in DFU mode if not already
		if (hwfly_dfu_ping())
		{
			// set HWFLY in DFU mode
			hwfly_enter_dfu();

			if (hwfly_dfu_ping())
			{
				EPRINTF("DFU doesn't respond..\n");
				goto out;
			}
		}

		// print info
		gfx_printf("\nFlashing FW...\n");

		// set FW flash address
		if (hwfly_dfu_set_flash_addr(DFU_FW_OFFSET)) {
			EPRINTF("\nFailed to set flash address!\n");
			goto out;
		}

		uint8_t pct = 0;
		uint32_t prevPct = 200;
		uint32_t offset = 0;
		uint32_t remaining = size;

		// start flashing
		while (remaining)
		{
			// load and start xfer
			memset(&MMC_BUFFER[1], 0, DFU_XFER_BYTES);
			memcpy(&MMC_BUFFER[1], firmware + offset, MIN(remaining, DFU_XFER_BYTES));
			if (hwfly_dfu_xfer_start(DFU_XFER_BYTES, 10)) {
				EPRINTFARGS("\nFailed to flash (@ %08X)!\n", 0x8000000 + DFU_FW_OFFSET + offset);
				break;
			}

			pct = ((uint32_t)offset * 100) / size;
			if (pct > 100)
				pct = 100;
			if (pct != prevPct)
			{
				tui_pbar(0, gfx_con.y, pct, 0xFFFF9600, 0xFF551500);
				prevPct = pct;
			}

			offset += MIN(remaining, DFU_XFER_BYTES);
			remaining -= MIN(remaining, DFU_XFER_BYTES);
		}

		if (!remaining)
		{
			tui_pbar(0, gfx_con.y, 100, 0xFFFF9600, 0xFF551500);
			gfx_printf("\n\nFlashed, now verifying..\n");

			// start verification
			remaining = size;
			offset = 0;
			uint8_t buffer[64];
			while (remaining)
			{
				// load and start xfer
				memset(&MMC_BUFFER[1], 0, DFU_XFER_BYTES);

				if (hwfly_dfu_read_flash(DFU_FW_OFFSET + offset, buffer))
				{
					EPRINTFARGS("Verification failed at %08X: no response!\n", 0x8000000 + DFU_FW_OFFSET + offset);
					break;
				}

				if (memcmp(buffer, firmware + offset, MIN(remaining, DFU_XFER_BYTES)))
				{
					EPRINTFARGS("Verification mismatch at %08X: firmware corrupt!\n", 0x8000000 + DFU_FW_OFFSET + offset);
					break;
				}

				pct = ((uint32_t)offset * 100) / size;
				if (pct > 100)
					pct = 100;
				if (pct != prevPct)
				{
					tui_pbar(0, gfx_con.y, pct, 0xFF96FF00, 0xFF155500);
					prevPct = pct;
				}

				offset += MIN(remaining, DFU_XFER_BYTES);
				remaining -= MIN(remaining, DFU_XFER_BYTES);
			}

			if (!remaining)
			{
				tui_pbar(0, gfx_con.y, 100, 0xFF96FF00, 0xFF155500);
				gfx_printf("\nVerified successfully\n");
				if (force_update)
					f_unlink(".force_update");
			}
		}

		fw_version = new_version;
		free(firmware);
	}

out:
	sd_end();
	sdmmc_end(&emmc_sdmmc);
}

void hwfly_dump_fw()
{
	gfx_printf("Entering DFU mode...\n");

	sdmmc_init(&emmc_sdmmc, SDMMC_4, SDMMC_POWER_1_8, SDMMC_BUS_WIDTH_1, SDHCI_TIMING_MMC_ID, SDMMC_POWER_SAVE_DISABLE);

	// set HWFLY in DFU mode if not already
	if (hwfly_dfu_ping())
	{
		// set HWFLY in DFU mode
		hwfly_enter_dfu();

		if (hwfly_dfu_ping())
		{
			EPRINTF("DFU doesn't respond..\n");
			goto out;
		}
	}

	// start reading flashing
	uint8_t pct = 0;
	uint32_t prevPct = 200;
	uint32_t offset = DFU_FW_OFFSET;
	uint32_t fw_size = DFU_FLASH_SIZE - DFU_FW_OFFSET;
	uint32_t remaining = fw_size;
	void *firmware = calloc(fw_size, 1);
	while (remaining)
	{
		if (hwfly_dfu_read_flash(offset, firmware + offset - DFU_FW_OFFSET))
		{
			EPRINTFARGS("\nFailed to read flash (@ %05X)!\n", 0x8000000 + offset);
			break;
		}

		// get current fw version
		if ((offset - DFU_FW_OFFSET) == 0x140)
			fw_version = *(uint32_t *)(firmware + 0x150 - DFU_FW_OFFSET);

		pct = ((uint32_t)(offset - DFU_FW_OFFSET) * 100) / fw_size;
		if (pct > 100)
			pct = 100;
		if (pct != prevPct) {
			tui_pbar(0, gfx_con.y, pct, 0xFF96FF00, 0xFF155500);
			prevPct = pct;
		}

		offset += DFU_XFER_BYTES;
		remaining -= DFU_XFER_BYTES;
	}

	if (!remaining)
	{
		tui_pbar(0, gfx_con.y, 100, 0xFF96FF00, 0xFF155500);
		gfx_printf("\nRead successfully!\nSaving to dumped_firmware.bin..\n");

		sd_mount();
		sd_save_to_file(firmware, fw_size, "dumped_firmware.bin");
		sd_end();
	}

	free(firmware);

out:
	sdmmc_end(&emmc_sdmmc);
}

void hwfly_enter_deep_sleep()
{
	sdmmc_init(&emmc_sdmmc, SDMMC_4, SDMMC_POWER_1_8, SDMMC_BUS_WIDTH_1, SDHCI_TIMING_MMC_ID, SDMMC_POWER_SAVE_DISABLE);
	hwfly_enable_deep_sleep();
	sdmmc_end(&emmc_sdmmc);
}

uint32_t hwfly_reset_train_data()
{
	sdmmc_init(&emmc_sdmmc, SDMMC_4, SDMMC_POWER_1_8, SDMMC_BUS_WIDTH_1, SDHCI_TIMING_MMC_ID, SDMMC_POWER_SAVE_DISABLE);
	uint32_t res = hwfly_train_data_reset();
	sdmmc_end(&emmc_sdmmc);

	return res;
}

uint32_t hwfly_get_train_data(uint32_t *load_result, config_t *cfg)
{
	sdmmc_init(&emmc_sdmmc, SDMMC_4, SDMMC_POWER_1_8, SDMMC_BUS_WIDTH_1, SDHCI_TIMING_MMC_ID, SDMMC_POWER_SAVE_DISABLE);
	uint32_t res = hwfly_train_data_get(load_result, cfg);
	sdmmc_end(&emmc_sdmmc);
	return res;
}

uint32_t hwfly_set_train_data(config_t *cfg)
{
	sdmmc_init(&emmc_sdmmc, SDMMC_4, SDMMC_POWER_1_8, SDMMC_BUS_WIDTH_1, SDHCI_TIMING_MMC_ID, SDMMC_POWER_SAVE_DISABLE);
	uint32_t res = hwfly_train_data_set(cfg);
	sdmmc_end(&emmc_sdmmc);
	return res;
}

uint32_t hwfly_session_info(uint8_t *fmt, session_info_t *si)
{
	sdmmc_init(&emmc_sdmmc, SDMMC_4, SDMMC_POWER_1_8, SDMMC_BUS_WIDTH_1, SDHCI_TIMING_MMC_ID, SDMMC_POWER_SAVE_DISABLE);
	uint32_t res = hwfly_session_info_get(fmt, si);
	sdmmc_end(&emmc_sdmmc);
	return res;
}

void hwfly_exit_dfu_and_launch_firmware()
{
	sdmmc_init(&emmc_sdmmc, SDMMC_4, SDMMC_POWER_1_8, SDMMC_BUS_WIDTH_1, SDHCI_TIMING_MMC_ID, SDMMC_POWER_SAVE_DISABLE);
	// check if in DFU mode and exit
	if (!hwfly_dfu_ping())
		hwfly_exit_dfu();
	else
		EPRINTF("Not in DFU mode..\n");
	sdmmc_end(&emmc_sdmmc);
}
