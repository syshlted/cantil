# XIAO BLE Sense LSM6DS3TR-C — Debug Timeline

A chronological record of the effort to get the on-board LSM6DS3TR-C accelerometer/gyro working on the Seeed Studio XIAO BLE Sense (nRF52840), for use as a tap-gesture input source. The investigation began on 2026-05-19 and was provisionally closed on 2026-05-20 with a "chip dead on both units" verdict, then re-opened on 2026-05-24 when a community forum lead surfaced an alternative root cause we had not tested.

Saved as a historical record. The story is a textbook case of what happens when a hardware vendor ships a board with on-board peripherals that are not documented at the schematic / pinmap level a system-software engineer needs in order to write a driver from first principles.

---

## Hardware under test

- **Board:** Seeed Studio XIAO BLE Sense (nRF52840 SoC)
- **IMU:** STMicroelectronics LSM6DS3TR-C (6-axis accel + gyro with hardware tap-detection interrupts)
- **Two physical units tested.** Tracked by FICR DEVICEID serial:
  - Unit #1: `69A3031F0204C8EE`
  - Unit #2: (second board, identical behaviour)
- **Toolchain:** Nordic Connect SDK (NCS) v3.0.2 / Zephyr, GCC ARM none-eabi via distrobox
- **Driver attempted:** upstream Zephyr `LSM6DSL` driver (the closest in-tree match for the LSM6DS3TR-C)

---

## Timeline of findings

### 2026-05-18 and earlier — baseline assumptions

The board DTS shipped in NCS / Zephyr (`xiao_ble_common.dtsi` plus the `sense` variant DTS) declares an `lsm6ds3tr_c` node on `i2c0` at address `0x6A` with interrupt on `gpio0` pin 11. The application overlay `firmware/boards/xiao_ble_nrf52840_sense.overlay` consumed that node as-is. No questions were raised at this point about which I2C controller or pinctrl group the IMU was wired to — the assumption was that the board file was correct.

### 2026-05-19 — first deep debug session (conversation_005)

**Commits:** `374082e`, `fe766da` — *"debug(imu): USB-serial logging + thorough I2C diagnostics, LSM6DSL driver off."*

Starting symptom: the existing `tap_imu.c` from earlier work appeared to be wishful thinking. A read of the Zephyr `LSM6DSL` driver source at `~/ncs/v3.0.2/zephyr/drivers/sensor/st/lsm6dsl/lsm6dsl_trigger.c` revealed that the in-tree driver exposed only data-ready triggers — no tap / double-tap / orientation / 6D / single-tap / free-fall handlers. The whole "use the driver's tap event API" path was a dead end; tap support would have to be programmed via direct I2C register writes to TAP_CFG / TAP_THS_6D / WAKE_UP_THS / WAKE_UP_DUR / MD1_CFG.

Wrote a replacement `tap_imu.c` that:
- Pulled the I2C bus and IRQ GPIO from the `lsm6ds3tr_c` DT node by `DT_NODELABEL`.
- Programmed the tap-config registers directly.
- Added extensive LED-based diagnostic blink codes for each I2C step.

Added USB-serial diagnostic logging from inside `tap_imu.c`, including a direct probe of address `0x6A` with a WHO_AM_I (`0x0F`) read and a full I2C bus scan from `0x08`..`0x77`.

**Result:** `direct probe 0x6A WHO_AM_I -> -5 (-EIO)`. Bus scan: 0 devices found, at both 100 kHz and 400 kHz. The TWIM peripheral itself initialized cleanly; SDA and SCL idled HIGH both before and after the load-switch enable on P1.08.

**Things tried in this session (all unsuccessful):**

| Attempt | Outcome |
| --- | --- |
| Direct I2C address scan with `i2c_write` zero-byte writes | Reported phantom hit at `0x09` — Nordic TWIM does not NACK zero-byte writes correctly, so this method is unreliable |
| `CONFIG_LSM6DSL_TRIGGER_GLOBAL_THREAD=y` | No effect |
| `CONFIG_REGULATOR=n` + drive P1.08 manually | Bus still silent |
| Explicit `regulator_enable(imu_regulator)` call | Bus still silent |
| `regulator_enable()` + forced direct GPIO drive on P1.08 | Bus still silent |
| Lowered bus speed from 400 kHz to 100 kHz | Bus still silent |
| Disabled upstream LSM6DSL driver entirely | Bus still silent |

**Conclusion at end of session:** the chip appears to not be on the I2C bus. P1.08 readback (with `GPIO_INPUT` enabled) confirmed the load-switch enable line was driven HIGH; pull-ups on the bus were behaving correctly. Status recorded in memory file `project_tap_imu_debug.md`.

**Followups identified:**
- Build and flash the upstream Zephyr `samples/sensor/lsm6dsl` sample to act as a gold standard. If the upstream sample also can't see the chip, the failure is below our application code.
- Probe P1.08 and SDA/SCL with a logic analyser for ground truth.
- Try `i2c_recover_bus` in case of stuck bus.

### 2026-05-19 — upstream LSM6DSL sample verdict

**Commits:** `5eae8c4`, `8978ee1` — *"debug(imu): upstream LSM6DSL driver verdict — chip silent on this hardware."*

Built and flashed the upstream `samples/sensor/lsm6dsl` sample for `xiao_ble/nrf52840/sense`. Same result: chip not detected, `device_is_ready()` returns FALSE.

This was the gold-standard test we identified as the followup from the previous session. The upstream sample does not depend on any of our application code; it uses the in-tree board DTS as-is. Its failure was treated as strong evidence that the issue was not in our overlay or driver code but in the chip itself or its I2C path.

### 2026-05-19 — PDM smoke-test on both units

Built a `FILE_SUFFIX=pdm_smoketest` variant that initializes the on-board PDM digital microphone (separate peripheral, separate analog rail at P1.10) and reports an RMS / peak audio sample.

Both XIAO units booted cleanly, enumerated `/dev/ttyACM*`, and reported identical idle noise floors (peak=7, rms=7). This proved the boards were not generally broken — the MEMS mic and its regulator were working on the same unit that the IMU was silent on. The silence was isolated to the LSM6DS3TR-C and its I2C path, not a board-wide analog or digital frontend failure.

### 2026-05-20 — final power-cycle attempt, IMU declared CLOSED

**Commits:** `d319a6b`, `2acc570` — *"debug(imu): 500ms power-cycle on unit #1 — chip still silent, IMU closed."*

The last untested variable was incomplete capacitor discharge during the load-switch power cycle on P1.08. Lengthened the rail-LOW window from 100 ms to 500 ms, with an explicit 50 ms post-HIGH settle delay. Added a boot-time FICR DEVICEID log so future sessions can verify which physical board is in play from the serial output alone.

**Result:** `direct probe 0x6A WHO_AM_I -> -5 (-EIO)`. No change.

**Verdict recorded in memory:** "The chip is electrically dead on this unit. Same conclusion for both units. IMU is permanently abandoned for this project on this hardware. Pivot to PDM mic tap detection (proven alive on both units via smoketest 2026-05-19). GPIO button as secondary fallback."

### 2026-05-21 — pivot committed

**Commits:** `7052092`, `f0bda1a` — *"feat(pdm-smoketest): minimal DMIC capture build for hardware verification."*

PDM smoke-test code permanently committed as the foundation for an onset-detector tap input. Subsequent design work (color-palette gesture alphabet, navigation graph, LED palette) proceeded on the assumption that the input source would be PDM mic or GPIO button, both impulse-only — no hardware ST/DT distinction available.

### 2026-05-24 — re-opened by community forum lead

While planning the implementation phase for the tap/LED system, a PlatformIO community forum thread surfaced. A user reporting the same symptom — "Cannot initialize IMU on XIAO Sense nRF52840" — resolved it by switching libraries:

- **External references:**
  - [https://community.platformio.org/t/cannot-initialize-imu-on-xiao-sense-nrf52840/41254](https://community.platformio.org/t/cannot-initialize-imu-on-xiao-sense-nrf52840/41254)
  - [https://registry.platformio.org/libraries/seeed-studio/Seeed%20Arduino%20LSM6DS3](https://registry.platformio.org/libraries/seeed-studio/Seeed%20Arduino%20LSM6DS3)
- **Failing library:** `arduino-libraries/Arduino_LSM6DS3` (generic Arduino library, designed for Arduino Nano 33 IoT and Uno WiFi Rev2)
- **Working library:** `seeed-studio/Seeed Arduino LSM6DS3` (Seeed's board-specific variant)
- **Reported root cause (forum, user-supplied):** "the I2C bus being the wrong one." The XIAO BLE Sense routes the IMU on a **separate internal I2C bus**, not the externally-exposed I2C pins. The Arduino library was configured for the external bus and never reached the chip.

The Zephyr-equivalent question becomes: in the board DTS `xiao_ble_common.dtsi`, which I2C controller is the `lsm6ds3tr_c` node attached to, and which pinctrl group does that controller use? If the in-tree board DTS routes the IMU node to a controller whose pinctrl points at the external I2C pins (`P0.04` / `P0.05`) instead of the documented internal IMU pins (`P0.07` / `P0.27`), every probe at `0x6A` would NACK — identical to the symptoms we observed, and consistent across both units (because both are running the same board DTS).

**This was never tested.** Throughout the 2026-05-19 to 2026-05-20 investigation, the working assumption was that the upstream board DTS routed the IMU to the correct I2C controller and pinctrl. The two units behaving identically was interpreted as "two units of bad silicon"; in retrospect, two units behaving identically is at least as consistent with "the same software bug on both."

**Status:** re-opened, scheduled for the next session. Investigation plan: read the actual pinctrl group used by the `i2c0` (or whichever controller the IMU is on) in the XIAO BLE Sense board DTS, compare against the documented internal IMU I2C pins (`P0.07` SDA / `P0.27` SCL), and if there's a mismatch, write an overlay that re-routes the controller to the correct pins. If the pinctrl is already correct, the original "chip dead" verdict stands.

### 2026-05-24 (later) — forum lead ruled out, investigation re-closed

Read the in-tree NCS v3.0.2 board DTS to settle the pinctrl question:

- `~/ncs/v3.0.2/zephyr/boards/seeed/xiao_ble/xiao_ble_nrf52840_sense.dts` binds `lsm6ds3tr_c@6a` to `&i2c0`.
- `~/ncs/v3.0.2/zephyr/boards/seeed/xiao_ble/xiao_ble-pinctrl.dtsi` defines `i2c0_default` with `TWIM_SDA = P0.07` and `TWIM_SCL = P0.27` — the documented **internal** IMU bus pins. `i2c1` is what's wired to the external pads (P0.04 / P0.05).
- The IMU power gate `lsm6ds3tr-c-en` on P1.08 has `regulator-boot-on` + 3 ms startup; `CONFIG_REGULATOR_FIXED` defaults `y` when the DT compatible is present, and our `tap_imu.c` additionally calls `regulator_enable()` and force-drives P1.08 with an explicit power-cycle.

**Conclusion:** the forum's "wrong I2C bus" diagnosis applies to the Arduino library ecosystem, not to the Zephyr in-tree build. Our DTS is already on the correct internal bus, and the rail is being asserted. The lead does not explain our failure.

Cross-checked against the existing diagnostic results recorded above for this same date:

- Full I2C scan 0x08..0x77 already executed on **both units**, at **both 100 kHz and 400 kHz** — 0 devices found in every combination.
- SDA and SCL idle HIGH before and after enabling the load switch (pull-ups present, nothing held low).

No firmware-level test remains that could overturn the verdict. Only hardware-level steps would: scope or logic-analyzer the SDA/SCL pins to confirm START conditions are actually appearing on the lines, or test a third unit. The dead-silicon verdict from 2026-05-20 is **re-affirmed and the investigation is closed again**. PDM mic remains the tap input; GPIO button remains the secondary fallback path for boards that have one.

---

## Lessons / commentary for the historical record

1. **"Same failure on two units" is not the same as "two hardware failures."** When two identically-configured boards behave identically, the prior probability of a shared software / configuration bug is much higher than the prior probability of two correlated silicon failures. The investigation should have weighted that more heavily before declaring the chip dead.

2. **The community forum lead would have been findable on day one.** A web search for the exact symptom string ("Cannot initialize IMU on XIAO Sense nRF52840") was not run during the original investigation. It would have surfaced the PlatformIO thread, the "wrong I2C bus" diagnosis, and the Seeed library reference. This is a process lesson worth carrying forward: when a peripheral on a vendor board is silent and the diagnostic steps don't converge, search community forums for the exact board + chip combination before concluding hardware failure.

3. **Vendor documentation gap.** Seeed Studio publishes the XIAO BLE Sense as an off-the-shelf development board with the LSM6DS3TR-C and PDM mic as advertised features, but does not publish a clear top-level pinout document that, for a system-software engineer writing against Zephyr (not Arduino), unambiguously says: *"the IMU is on a dedicated internal I2C bus at SDA=P0.07, SCL=P0.27, behind a load switch on P1.08."* The Arduino BSP encapsulates this in its `Seeed_Arduino_LSM6DS3` library; the in-tree Zephyr board DTS encodes it (correctly or incorrectly) in `xiao_ble_common.dtsi`. Neither makes it explicit to someone outside that ecosystem. The forum thread is, effectively, the de-facto documentation.

4. **The upstream Zephyr sample didn't help us — but for the same reason.** When `samples/sensor/lsm6dsl` also failed to find the chip, we treated it as confirmation of hardware failure. But the upstream sample uses the same board DTS we did; if the board DTS has a pinctrl bug, the sample has the same bug, and a passing sample would have been the only useful signal. Gold-standard tests only work as a baseline if they exercise an independent code path. Our gold standard shared the suspect code with us, and we didn't notice.

5. **The pivot was not wasted.** Even if the IMU comes back, the redesign that followed — count-then-pause color alphabet, gesture navigation graph, full LED palette — is strictly better than the original ST/DT-only design (6⁶ ≈ 46.6k combinations versus 2⁶ = 64). The IMU, if it works, becomes a third tap input source alongside the GPIO button and PDM mic; it does not change the gesture or LED design.

---

## Related artifacts

- Memory: `project_tap_imu_debug.md` (CLOSED on 2026-05-20; historical state)
- Conversation transcripts: `docs/conversations/conversation_005.md` through `conversation_010.md` contain the live debug sessions
- Code (still present in tree, currently dormant): `firmware/src/gesture/tap_imu.c` and the IMU portions of `firmware/boards/xiao_ble_nrf52840_sense.overlay`
- PDM smoke-test build: `FILE_SUFFIX=pdm_smoketest` in the build scripts
