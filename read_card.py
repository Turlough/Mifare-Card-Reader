"""
Mifare card reader - monitors for cards and reads UID + data.

Supports: Mifare Classic 1K/4K, Mifare Ultralight, Mifare Mini
Requires: pip install pyscard
Run with Windows Python: python read_card.py
"""

import sys
import time

from smartcard.System import readers
from smartcard.util import toHexString
from smartcard.CardConnection import CardConnection
from smartcard.Exceptions import NoCardException, CardConnectionException

MIFARE_DEFAULT_KEY = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

ATR_CARD_TYPES = {
    "00 01": "Mifare Classic 1K",
    "00 02": "Mifare Classic 4K",
    "00 03": "Mifare Ultralight",
    "00 26": "Mifare Mini",
    "F0 04": "Mifare Plus SL1 2K",
    "F0 11": "Mifare Plus SL2 4K",
}


def identify_card(atr):
    """Identify card type from ATR. Returns (type_name, is_classic, is_ultralight)."""
    atr_hex = toHexString(atr)

    for pattern, name in ATR_CARD_TYPES.items():
        if pattern in atr_hex:
            is_classic = "Classic" in name or "Mini" in name or "Plus" in name
            is_ul = "Ultralight" in name
            return name, is_classic, is_ul

    if "A0 00 00 03 06" in atr_hex:
        return "Mifare (unknown)", False, False
    return f"Unknown", False, False


def get_uid(conn):
    data, sw1, sw2 = conn.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
    if sw1 == 0x90 and sw2 == 0x00:
        return data
    return None


def load_key(conn, key=None):
    if key is None:
        key = MIFARE_DEFAULT_KEY
    _, sw1, sw2 = conn.transmit([0xFF, 0x82, 0x00, 0x00, 0x06] + key)
    return sw1 == 0x90 and sw2 == 0x00


def auth_block(conn, block, key_type=0x60):
    """Authenticate block. key_type: 0x60=Key A, 0x61=Key B."""
    _, sw1, sw2 = conn.transmit(
        [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, key_type, 0x00]
    )
    return sw1 == 0x90 and sw2 == 0x00


def read_block(conn, block, length=16):
    data, sw1, sw2 = conn.transmit([0xFF, 0xB0, 0x00, block, length])
    if sw1 == 0x90 and sw2 == 0x00:
        return data
    return None


def to_ascii(data):
    return "".join(chr(x) if 32 <= x < 127 else "." for x in data)


def to_int_string(data):
    """Return bytes as comma-separated integer values."""
    return ", ".join(str(b) for b in data)


def bytes_to_bigint(data):
    """Interpret bytes as big-endian integer."""
    return sum(b << (8 * (len(data) - 1 - i)) for i, b in enumerate(data))


def read_ultralight(conn):
    """Read all pages from a Mifare Ultralight card."""
    print(f"\n  {'Page':>4}  {'Hex':.<24}  ASCII       {'Int (non-empty data)':<30}")
    print(f"  {'=' * 4}  {'=' * 24}  {'=' * 8}  {'=' * 30}")

    labels = {0: "UID-1", 1: "UID-2", 2: "lock", 3: "OTP"}
    total_pages = 0

    for page in range(128):
        data = read_block(conn, page, 4)
        if data is None:
            break
        total_pages += 1
        hex_str = toHexString(data)
        ascii_str = to_ascii(data)
        label = labels.get(page, "data" if page >= 4 else "")
        non_zero = any(b != 0 for b in data) if page >= 4 else True
        marker = " *" if non_zero and page >= 4 else ""
        int_str = to_int_string(data) if (non_zero and page >= 4) else ""
        print(f"  {page:>4}  {hex_str:<24}  {ascii_str:<8}  {int_str:<30}  {label}{marker}")

    print(f"\n  Total pages: {total_pages} ({total_pages * 4} bytes)")


def read_classic(conn, card_type):
    """Read all sectors from a Mifare Classic card."""
    if "4K" in card_type:
        num_sectors = 40
    elif "Mini" in card_type:
        num_sectors = 5
    else:
        num_sectors = 16

    blocks_per_sector = 4

    if not load_key(conn):
        print("  Failed to load authentication key")
        return

    print(f"\n  {'Block':>5}  {'Sect':>4}  {'Hex Data':<48}  ASCII       Int (non-empty)")
    print(f"  {'=' * 5}  {'=' * 4}  {'=' * 48}  {'=' * 16}  {'=' * 30}")

    for sector in range(min(num_sectors, 16)):
        first_block = sector * blocks_per_sector
        authenticated = auth_block(conn, first_block)

        for b in range(blocks_per_sector):
            block_num = first_block + b
            if not authenticated:
                print(f"  {block_num:>5}  {sector:>4}  {'(auth failed)':<48}")
                continue

            data = read_block(conn, block_num)
            if data:
                hex_str = toHexString(data)
                ascii_str = to_ascii(data)
                is_data_block = block_num != 0 and b != blocks_per_sector - 1
                non_empty = is_data_block and any(x != 0 for x in data)
                int_str = to_int_string(data) if non_empty else ""
                tag = ""
                if block_num == 0:
                    tag = " [manufacturer]"
                elif b == blocks_per_sector - 1:
                    tag = " [sector trailer]"
                print(f"  {block_num:>5}  {sector:>4}  {hex_str:<48}  {ascii_str:<16}  {int_str:<30}{tag}")
            else:
                print(f"  {block_num:>5}  {sector:>4}  {'(read failed)':<48}")

    # Sectors 16-39 in 4K cards use 16 blocks each
    if num_sectors > 16:
        for sector in range(16, num_sectors):
            bps = 16
            first_block = 128 + (sector - 16) * bps
            authenticated = auth_block(conn, first_block)
            for b in range(bps):
                block_num = first_block + b
                if not authenticated:
                    print(f"  {block_num:>5}  {sector:>4}  {'(auth failed)':<48}")
                    continue
                data = read_block(conn, block_num)
                if data:
                    hex_str = toHexString(data)
                    ascii_str = to_ascii(data)
                    is_data_block = b != bps - 1
                    non_empty = is_data_block and any(x != 0 for x in data)
                    int_str = to_int_string(data) if non_empty else ""
                    tag = " [sector trailer]" if b == bps - 1 else ""
                    print(
                        f"  {block_num:>5}  {sector:>4}  {hex_str:<48}  {ascii_str:<16}  {int_str:<30}{tag}"
                    )
                else:
                    print(f"  {block_num:>5}  {sector:>4}  {'(read failed)':<48}")


def uid_to_card_number(uid):
    """Derive the 10-digit card number from UID (4-byte UID as big-endian uint32)."""
    if uid and len(uid) == 4:
        return int.from_bytes(uid, "big")
    if uid and len(uid) == 7:
        return int.from_bytes(uid[-4:], "big")
    return None


def read_card(conn):
    """Read a card, auto-detecting its type."""
    atr = conn.getATR()
    card_type, is_classic, is_ultralight = identify_card(atr)

    uid = get_uid(conn)
    uid_str = toHexString(uid) if uid else "unknown"
    card_number = uid_to_card_number(uid)

    print(f"  Card Type : {card_type}")
    print(f"  UID       : {uid_str}")
    if card_number is not None:
        print(f"  Card No.  : {card_number}")
    print(f"  ATR       : {toHexString(atr)}")

    if is_ultralight:
        read_ultralight(conn)
    elif is_classic:
        read_classic(conn, card_type)
    else:
        # Try Ultralight-style read first, fall back to Classic
        print("\n  Attempting Ultralight-style read...")
        test = read_block(conn, 0, 4)
        if test:
            read_ultralight(conn)
        else:
            print("  Attempting Classic-style read...")
            read_classic(conn, card_type)

    return uid_str


def select_reader():
    reader_list = readers()
    if not reader_list:
        print("No smart card readers found.")
        sys.exit(1)

    print("Readers:")
    for i, r in enumerate(reader_list):
        print(f"  [{i}] {r}")

    nfc = [r for r in reader_list if "NFC" in str(r) or "contactless" in str(r).lower()]
    return nfc[0] if nfc else reader_list[0]


def main():
    print("=" * 60)
    print("  Mifare Card Reader")
    print("=" * 60)

    target = select_reader()
    print(f"\nUsing: {target}")
    print("Place a card on the reader... (Ctrl+C to quit)\n")

    last_uid = None

    while True:
        try:
            conn = target.createConnection()
            conn.connect(CardConnection.T0_protocol | CardConnection.T1_protocol)

            uid_str = None
            try:
                uid = get_uid(conn)
                uid_str = toHexString(uid) if uid else None
            except Exception:
                pass

            if uid_str and uid_str != last_uid:
                last_uid = uid_str
                print(f"{'=' * 60}")
                read_card(conn)
                print(f"{'=' * 60}\n")
                print("Waiting for next card...")

            conn.disconnect()

        except (NoCardException, CardConnectionException):
            if last_uid is not None:
                print("Card removed.\n")
                last_uid = None
        except Exception:
            if last_uid is not None:
                last_uid = None

        time.sleep(0.5)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
