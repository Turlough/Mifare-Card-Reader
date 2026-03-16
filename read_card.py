"""
Mifare card reader - monitors for cards and displays the card number.

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
    card_type, _, _ = identify_card(atr)

    uid = get_uid(conn)
    uid_str = toHexString(uid) if uid else "unknown"
    card_number = uid_to_card_number(uid)

    # Emphasise the card number - this is the value the user needs
    if card_number is not None:
        print()
        print("=" * 40)
        print(f"\t  Card Type : {card_type}")
        print(f"\t  UID       : {uid_str}")

        print(f"\nCARD NUMBER: {card_number}\n")
        print("=" * 40)

    else:
        print("  Card No.  : (could not derive from UID)")

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
    print(f"Using: {target}")
    print("Place a card on the reader... (Ctrl+C to quit)")

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

                read_card(conn)

                print("Waiting for next card...")

            conn.disconnect()

        except (NoCardException, CardConnectionException):
            if last_uid is not None:
                print("Card removed.")
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
