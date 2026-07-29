# GPIO Map -- EdgeHax S3 Pro

| ESP32-S3 GPIO | Signal              | Component                          |
|---------------|---------------------|-------------------------------------|
| GPIO 1        | SDA                 | I2C Bus (DS3231 + MPU6050)          |
| GPIO 2        | SCL                 | I2C Bus (DS3231 + MPU6050)          |
| GPIO 3        | Free / unused        | Originally the INMP441 mic pin, abandoned due to a GPIO3 strapping-pin / CS4344 MCLK clock conflict that made reliable mic capture impractical on this board revision. A potentiometer was briefly planned for this pin but has since been dropped -- GPIO3 is currently unused and available for future assignment |
| GPIO 4        | CS                  | SPI TFT Display                     |
| GPIO 5        | RESET               | SPI TFT Display                     |
| GPIO 6        | Button Ladder Line   | 5x Hardware Switches                |
| GPIO 7        | DC / RS             | SPI TFT Display                     |
| GPIO 8        | INT                 | MPU6050 Accelerometer               |
| GPIO 9        | MCLK                | CS4344 Audio DAC                    |
| GPIO 10       | SD_CS               | On-board microSD Slot               |
| GPIO 11       | SD_MOSI             | On-board microSD Slot               |
| GPIO 12       | SD_SCK              | On-board microSD Slot               |
| GPIO 13       | SD_MISO             | On-board microSD Slot               |
| GPIO 14       | T_CS                | Touch Screen Controller (XPT2046)   |
| GPIO 15       | MOSI / T_DIN        | Shared SPI (Display + Touch)        |
| GPIO 16       | SCK / T_CLK         | Shared SPI (Display + Touch)        |
| GPIO 17       | SQW                 | DS3231 Real-Time Clock              |
| GPIO 18       | 32K                 | DS3231 Real-Time Clock              |
| GPIO 19       | D-                  | Native USB-C                        |
| GPIO 20       | D+                  | Native USB-C                        |
| GPIO 21       | LRCLK / WS          | Shared I2S (DAC output only -- mic removed) |
| GPIO 38       | SDIN                | CS4344 Audio DAC (-> passive buzzer)|
| GPIO 39       | MISO / SDO          | SPI TFT Display Only                |
| GPIO 40       | OUT                 | TTP223 Touch Sensor                 |
| GPIO 41       | T_DO                | Touch Screen Controller (XPT2046)   |
| GPIO 42       | BCLK                | Shared I2S (DAC output only -- mic removed) |

**GPIO 26-37**: reserved internally by the ESP32-S3 module for SPI flash and
octal PSRAM. Not broken out, not usable.

## Notes

- **Microphone removed from this revision.** GPIO3 (originally the INMP441
  data line) is a strapping pin, and combined with clock interference from
  the CS4344's MCLK on the shared I2S bus, reliable mic capture wasn't
  achievable on this hardware layout. A potentiometer was briefly planned
  as a replacement use for GPIO3 but has since been dropped -- **GPIO3 is
  currently free and unused.** It remains safe to reuse for a future
  purpose: strapping pins are only sampled by the ROM bootloader in the
  first microseconds of power-on and behave as completely normal GPIOs
  for the rest of runtime.
- **I2S bus is now TX-only** (DAC/buzzer output), since the mic (RX) was
  removed. `dout`/`mclk`/`bclk`/`ws` are all still shared with what was
  previously a full-duplex config; no code changes needed there beyond
  no longer initializing/reading an RX channel.
