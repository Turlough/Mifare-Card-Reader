# Mifare Card Reader

A Python application for reading Mifare contactless smart cards via PC/SC-compatible NFC readers. Displays card type, UID, and the derived 10-digit card number.

## Supported Card Types

- Mifare Classic 1K / 4K
- Mifare Ultralight
- Mifare Mini
- Mifare Plus SL1 2K / SL2 4K

## Requirements

- Windows (PC/SC smart card API)
- Python 3.14+
- A PC/SC-compatible NFC or contactless card reader

## Installation

```bash
pip install -e .
```

Or install dependencies manually:

```bash
pip install pyscard flask pyperclip
```

## Usage

### Command-line mode

Monitor for cards and print the card number when detected:

```bash
python read_card.py
```

Place a card on the reader. The script will display the card type, UID, and derived card number. Press `Ctrl+C` to quit.

### Web interface

Run the Flask web app for a browser-based interface with auto-copy to clipboard and a history of cards read:

```bash
python card_reader_web.py
```

Then open **http://127.0.0.1:5000** in your browser. Place a card on the reader to see it detected; the card number is automatically copied to the clipboard.

## How It Works

- Uses the **pyscard** library to communicate with PC/SC readers
- Reads the card UID via the `GET DATA` APDU (`FF CA 00 00 00`)
- Derives the 10-digit card number from the 4-byte UID (big-endian uint32)
- Identifies card type from the ATR (Answer to Reset)
- Prefers NFC/contactless readers when multiple readers are available

## Project Structure

| File | Description |
|------|-------------|
| `read_card.py` | CLI card reader; polls for cards and prints card number |
| `card_reader_web.py` | Flask web app; same logic with web UI and clipboard copy |
| `pyproject.toml` | Project metadata and dependencies |

## License

See project license file.
