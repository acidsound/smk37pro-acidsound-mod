idf_component_register(
    SRCS "usbkey_main.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES esp_driver_gpio esp_driver_usb_serial_jtag vfs
)
