#include "rtc_manager.h"
#include "board_config.h"
#include <Wire.h>

static byte bcd2d(byte b) { return (b >> 4) * 10 + (b & 0x0F); }
static byte d2bcd(byte v) { return ((v / 10) << 4) | (v % 10); }

// Howard Hinnant's days_from_civil / civil_from_days
static int32_t daysFromCivil(int y, int m, int d) {
  y -= m <= 2;
  int32_t era = (y >= 0 ? y : y - 399) / 400;
  unsigned yoe = (unsigned)(y - era * 400);
  unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + (int32_t)doe - 719468;
}

static void civilFromDays(int32_t z, int& y, unsigned& m, unsigned& d) {
  z += 719468;
  int32_t era = (z >= 0 ? z : z - 146096) / 146097;
  unsigned doe = (unsigned)(z - era * 146097);
  unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  y = (int)yoe + era * 400;
  unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  unsigned mp = (5 * doy + 2) / 153;
  d = doy - (153 * mp + 2) / 5 + 1;
  m = mp + (mp < 10 ? 3 : -9);
  y += (m <= 2);
}

bool RtcManager::begin() {
  Wire.begin(RTC_SDA, RTC_SCL);
  Wire.setClock(100000);
  Wire.beginTransmission(RTC_I2C_ADDR);
  bool ping = (Wire.endTransmission() == 0);

  // A bare 0-byte address ping can ACK even when a real 7-byte register
  // read afterward doesn't come back (bus glitch, a peripheral that inits
  // later drawing a brown-out, etc). Do one real read here too, so isOK()
  // -- and the "RTC: OK" boot line -- actually means "I can read the
  // clock," not just "something answered." Previously this was ping-only,
  // which could report OK while every later unixEpoch() call was quietly
  // failing and returning 0.
  byte h, m, s, dow, day, mon; int year;
  readFull(h, m, s, dow, day, mon, year);

  _ok = ping && (h != 255);
  return _ok;
}

void RtcManager::readFull(byte& h, byte& m, byte& s, byte& dow, byte& day, byte& mon, int& year) {
  h = m = s = 255; dow = day = mon = 0; year = 0;
  Wire.beginTransmission(RTC_I2C_ADDR);
  Wire.write(0x00);
  // NOTE: this used to be Wire.endTransmission(false) -- a repeated-START,
  // which is spec-legal and what most DS3231 libraries do, but which was
  // silently failing on this board (S3 + this arduino-esp32 core combo
  // apparently doesn't handle it), leaving Wire.available() at 0 and every
  // field stuck at its sentinel default. That's what was masquerading as
  // "RTC lost its time" -- it never got as far as talking to the chip's
  // date registers at all. Switched to STOP-then-fresh-START, which is
  // exactly the pattern in the standalone test sketch that reads this same
  // chip on these same pins correctly.
  Wire.endTransmission();
  Wire.requestFrom(RTC_I2C_ADDR, (uint8_t)7);
  if (Wire.available() >= 7) {
    s   = bcd2d(Wire.read() & 0x7F);
    m   = bcd2d(Wire.read());
    h   = bcd2d(Wire.read() & 0x3F);
    dow = bcd2d(Wire.read());
    day = bcd2d(Wire.read());
    mon = bcd2d(Wire.read() & 0x1F);
    year = 2000 + bcd2d(Wire.read());
  }
}

uint32_t RtcManager::unixEpoch() {
  byte h, m, s, dow, day, mon; int year;
  readFull(h, m, s, dow, day, mon, year);
  if (h == 255) return 0;
  int32_t days = daysFromCivil(year, mon, day);
  return (uint32_t)days * 86400UL + (uint32_t)h * 3600UL + (uint32_t)m * 60UL + s;
}

bool RtcManager::readOSF() {
  // Status register 0x0F, bit 7 -- the DS3231 sets this itself whenever VCC
  // and VBAT have both dropped low enough that the oscillator actually
  // stopped. It's the chip's own admission that its time can't be trusted,
  // independent of whatever plausible-looking date happens to be sitting
  // in the registers. Once set, it stays set until firmware clears it --
  // the chip never clears it on its own, even after power is restored and
  // the oscillator is running fine again.
  Wire.beginTransmission(RTC_I2C_ADDR);
  Wire.write(0x0F);
  if (Wire.endTransmission() != 0) return false; // can't tell -- treat as "don't know"
  Wire.requestFrom(RTC_I2C_ADDR, (uint8_t)1);
  if (Wire.available() < 1) return false;
  byte status = Wire.read();
  return (status & 0x80) != 0;
}

void RtcManager::clearOSF() {
  Wire.beginTransmission(RTC_I2C_ADDR);
  Wire.write(0x0F);
  if (Wire.endTransmission() != 0) return;
  Wire.requestFrom(RTC_I2C_ADDR, (uint8_t)1);
  if (Wire.available() < 1) return;
  byte status = Wire.read();
  status &= ~0x80;
  Wire.beginTransmission(RTC_I2C_ADDR);
  Wire.write(0x0F);
  Wire.write(status);
  Wire.endTransmission();
}

void RtcManager::debugPrint(Stream& out) {
  byte h, m, s, dow, day, mon; int year;
  readFull(h, m, s, dow, day, mon, year);
  uint32_t epoch = unixEpoch();
  bool osf = readOSF();
  out.printf("[RTC] raw read: %04d-%02d-%02d %02d:%02d:%02d  epoch=%lu  sane=%s\n",
             year, mon, day, h, m, s,
             (unsigned long)epoch,
             (epoch >= SANE_EPOCH) ? "yes" : "NO -- this is why the device boots to SET TIME");
  if (osf) {
    out.println("[RTC] OSF (oscillator-stop flag) is SET -- the chip itself is reporting "
                "that backup power failed and its clock actually stopped. This means "
                "hardware, not firmware: check the CR2032/VBAT (missing, dead, reversed, "
                "or a rechargeable cell with no charge circuit). Setting the time will "
                "clear this flag, but it will come back if backup power is still bad.");
  } else if (h == 255) {
    out.println("[RTC] OSF read as clear, but the 7-byte time read failed -- this points "
                "to an I2C comms problem (wiring, address, missing pull-ups) rather than "
                "a lost-time problem. Run the I2C scan in diagnostics mode and confirm "
                "0x68 shows up.");
  }
}

void RtcManager::writeFromEpoch(uint32_t epoch) {
  int32_t days = epoch / 86400UL;
  uint32_t secOfDay = epoch % 86400UL;
  byte h = secOfDay / 3600;
  byte m = (secOfDay % 3600) / 60;
  byte s = secOfDay % 60;
  int year; unsigned mon, day;
  civilFromDays(days, year, mon, day);
  byte dow = (byte)(((days % 7) + 7 + 4) % 7) + 1;

  Wire.beginTransmission(RTC_I2C_ADDR);
  Wire.write(0x00);
  Wire.write(d2bcd(s));
  Wire.write(d2bcd(m));
  Wire.write(d2bcd(h));
  Wire.write(d2bcd(dow));
  Wire.write(d2bcd(day));
  Wire.write(d2bcd((byte)mon));
  Wire.write(d2bcd((byte)(year - 2000)));
  Wire.endTransmission();

  clearOSF(); // acknowledge: we just gave the chip a time we trust, so its own
              // "oscillator stopped, don't trust me" flag no longer applies.
              // Without this, OSF stays latched forever even after a correct
              // set, and would keep flagging as "hardware fault" on every
              // debugPrint even once the clock is genuinely fine again.
}