#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "driver/gpio.h"
#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

enum {
    USBKEY_DP_CLOCK_GPIO = GPIO_NUM_4,
    USBKEY_DM_DATA_GPIO = GPIO_NUM_5,
    USBKEY_VALUE = 0x16EF,
    USBKEY_BITS = 16,
    HALF_CLOCK_US = 10,
    INTERFRAME_LISTEN_US = 400,
    ATTACH_HIGH_SAMPLES = 3,
    SEND_WINDOW_MS = 15000,
};

static const char *TAG = "smk37-usbkey";
static const char *CONFIRMATION = "SEND USBKEY 16EF";

static void release_usb_lines(void) {
    gpio_set_direction(USBKEY_DP_CLOCK_GPIO, GPIO_MODE_INPUT);
    gpio_set_direction(USBKEY_DM_DATA_GPIO, GPIO_MODE_INPUT);
    gpio_pullup_dis(USBKEY_DP_CLOCK_GPIO);
    gpio_pullup_dis(USBKEY_DM_DATA_GPIO);
    gpio_pulldown_dis(USBKEY_DP_CLOCK_GPIO);
    gpio_pulldown_dis(USBKEY_DM_DATA_GPIO);
}

static void configure_usbkey_lines(void) {
    gpio_config_t config = {
        .pin_bit_mask = (1ULL << USBKEY_DP_CLOCK_GPIO) |
                        (1ULL << USBKEY_DM_DATA_GPIO),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&config));
    ESP_ERROR_CHECK(gpio_set_drive_capability(
        USBKEY_DP_CLOCK_GPIO, GPIO_DRIVE_CAP_0));
    ESP_ERROR_CHECK(gpio_set_drive_capability(
        USBKEY_DM_DATA_GPIO, GPIO_DRIVE_CAP_0));
    release_usb_lines();
}

static void configure_console_input(void) {
    usb_serial_jtag_driver_config_t config =
        USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&config));
    usb_serial_jtag_vfs_use_driver();
}

static void drive_usbkey_frame(void) {
    gpio_set_level(USBKEY_DP_CLOCK_GPIO, 0);
    gpio_set_level(USBKEY_DM_DATA_GPIO, 0);
    gpio_set_direction(USBKEY_DP_CLOCK_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_direction(USBKEY_DM_DATA_GPIO, GPIO_MODE_OUTPUT);

    for (int bit = USBKEY_BITS - 1; bit >= 0; --bit) {
        gpio_set_level(USBKEY_DP_CLOCK_GPIO, 0);
        gpio_set_level(USBKEY_DM_DATA_GPIO, (USBKEY_VALUE >> bit) & 1U);
        esp_rom_delay_us(HALF_CLOCK_US);
        gpio_set_level(USBKEY_DP_CLOCK_GPIO, 1);
        esp_rom_delay_us(HALF_CLOCK_US);
    }
    gpio_set_level(USBKEY_DP_CLOCK_GPIO, 0);
    release_usb_lines();
}

static bool listen_for_target_attach(void) {
    unsigned consecutive = 0;
    for (unsigned elapsed = 0; elapsed < INTERFRAME_LISTEN_US; elapsed += 10) {
        int dp = gpio_get_level(USBKEY_DP_CLOCK_GPIO);
        int dm = gpio_get_level(USBKEY_DM_DATA_GPIO);
        if (dp == 1 && dm == 0) {
            if (++consecutive >= ATTACH_HIGH_SAMPLES) {
                return true;
            }
        } else {
            consecutive = 0;
        }
        esp_rom_delay_us(10);
    }
    return false;
}

static bool send_usbkey_window(void) {
    const unsigned frame_us = USBKEY_BITS * HALF_CLOCK_US * 2U;
    const unsigned cycle_us = frame_us + INTERFRAME_LISTEN_US;
    const unsigned max_frames = (SEND_WINDOW_MS * 1000U) / cycle_us;

    ESP_LOGW(TAG, "USB_KEY output active: D+ clock=GPIO%d, D- data=GPIO%d",
             USBKEY_DP_CLOCK_GPIO, USBKEY_DM_DATA_GPIO);
    for (unsigned frame = 0; frame < max_frames; ++frame) {
        drive_usbkey_frame();
        if (listen_for_target_attach()) {
            release_usb_lines();
            ESP_LOGW(TAG, "candidate target D+ attach detected after %u frames", frame + 1);
            return true;
        }
    }
    release_usb_lines();
    ESP_LOGW(TAG, "send window ended without observing a target D+ attach");
    return false;
}

static void trim_line(char *line) {
    size_t length = strlen(line);
    while (length > 0 && isspace((unsigned char)line[length - 1])) {
        line[--length] = '\0';
    }
}

void app_main(void) {
    configure_usbkey_lines();
    configure_console_input();
    ESP_LOGI(TAG, "ready; GPIO4/GPIO5 are high-Z");
    ESP_LOGI(TAG, "no signal is generated automatically");
    printf("Type exactly: %s\n", CONFIRMATION);
    fflush(stdout);

    char line[96];
    for (;;) {
        if (fgets(line, sizeof(line), stdin) == NULL) {
            /*
             * Keep the confirmation loop safe if the VFS reports a temporary
             * empty read or EOF: clear stdio state and poll without driving.
             */
            clearerr(stdin);
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }
        trim_line(line);
        if (strcmp(line, CONFIRMATION) != 0) {
            ESP_LOGW(TAG, "rejected command; lines remain high-Z");
            printf("Type exactly: %s\n", CONFIRMATION);
            fflush(stdout);
            continue;
        }

        ESP_LOGW(TAG, "armed; output starts in 3 seconds");
        for (int seconds = 3; seconds > 0; --seconds) {
            ESP_LOGW(TAG, "%d", seconds);
            esp_rom_delay_us(1000000);
        }
        bool attached = send_usbkey_window();
        ESP_LOGI(TAG, "lines released to high-Z; candidate_attach=%s",
                 attached ? "yes" : "no");
        printf("Type exactly to retry: %s\n", CONFIRMATION);
        fflush(stdout);
    }

}
