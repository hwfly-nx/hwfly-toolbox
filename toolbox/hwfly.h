/*
 * Copyright (c) 2022 HWFLY
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

#ifndef _HWFLY_H_
#define _HWFLY_H_

#include <utils/types.h>

#define CONFIG_MAGIC 0x01584E53
#define SESSION_INFO_FORMAT_VER 1
#define SESSION_INFO_MAGIC 0x80B54D

typedef struct
{
	uint16_t offset;
	uint8_t width;
	uint32_t success;
} timing_t;

typedef struct
{
	uint32_t magic;
	uint32_t count;
	timing_t timings[32];
	uint8_t reflash;
} config_t;

typedef struct
{
	uint32_t width;
	uint32_t offset;
	uint32_t rng;
} glitch_cfg_t;

typedef struct
{
	uint16_t startup_adc_value;
	uint16_t glitch_attempt;
	uint32_t power_threshold_reached_us;
	uint32_t adc_goal_reached_us;
	uint32_t glitch_complete_us;
	uint32_t glitch_confirm_us;
	uint32_t flag_reads_before_glitch_confirmed;
	uint32_t total_time_us;

	uint8_t was_the_device_reset : 1;
	uint8_t payload_flashed : 1;
	uint8_t reserved : 6;

	glitch_cfg_t glitch_cfg;

} __attribute__((packed)) session_info_t;

void hwfly_dump_fw();
void hwfly_update_fw();
void hwfly_enter_deep_sleep();
uint32_t hwfly_reset_train_data();
uint32_t hwfly_get_train_data(uint32_t *load_result, config_t *si);
uint32_t hwfly_set_train_data(config_t *si);
uint32_t hwfly_session_info(uint8_t *fmt, session_info_t *si);

void hwfly_exit_dfu_and_launch_firmware();

#endif
