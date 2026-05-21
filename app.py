from flask import (
    Flask,
    render_template,
    request,
    send_from_directory,
    url_for
)

from PIL import Image

import os
import uuid
import struct
import base64

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)

UPLOAD_FOLDER = "static/uploads"
OUTPUT_FOLDER = "outputs"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)


# DOWNLOAD ROUTE 
@app.route("/download/<filename>")
def download_file(filename):
    return send_from_directory(
        OUTPUT_FOLDER,
        filename,
        as_attachment=True
    )


# AES 
def encrypt_bytes(data: bytes, password: str) -> bytes:
    salt = get_random_bytes(16)

    key = PBKDF2(
        password,
        salt,
        dkLen=32
    )

    cipher = AES.new(
        key,
        AES.MODE_CBC
    )

    encrypted = cipher.encrypt(
        pad(data, AES.block_size)
    )

    return salt + cipher.iv + encrypted


def decrypt_bytes(
    encrypted_data: bytes,
    password: str
) -> bytes:

    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]

    key = PBKDF2(
        password,
        salt,
        dkLen=32
    )

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv
    )

    decrypted = unpad(
        cipher.decrypt(ciphertext),
        AES.block_size
    )

    return decrypted


# BIT HELPERS 
def bytes_to_bits(data: bytes) -> str:
    return ''.join(
        format(byte, "08b")
        for byte in data
    )


def bits_to_bytes(bits: str) -> bytes:
    data = bytearray()

    for i in range(0, len(bits), 8):
        byte = bits[i:i + 8]

        if len(byte) == 8:
            data.append(
                int(byte, 2)
            )

    return bytes(data)


# PAYLOAD 
def create_payload(
    data: bytes,
    file_type: str,
    filename: str
) -> bytes:

    type_bytes = file_type.encode("utf-8")
    name_bytes = filename.encode("utf-8")

    payload = (
        struct.pack("B", len(type_bytes)) +
        type_bytes +
        struct.pack(">H", len(name_bytes)) +
        name_bytes +
        data
    )

    return payload


def parse_payload(payload: bytes):
    type_len = payload[0]
    index = 1

    file_type = payload[
        index:index + type_len
    ].decode("utf-8")

    index += type_len

    name_len = struct.unpack(
        ">H",
        payload[index:index + 2]
    )[0]

    index += 2

    filename = payload[
        index:index + name_len
    ].decode("utf-8")

    index += name_len

    data = payload[index:]

    return file_type, filename, data


#  LSB ENCODE 
def encode_lsb(
    image: Image.Image,
    secret_data: bytes
):

    img = image.convert("RGB")

    pixels = img.load()
    assert pixels is not None

    width, height = img.size

    length_data = struct.pack(
        ">I",
        len(secret_data)
    )

    full_data = length_data + secret_data

    bits = bytes_to_bits(full_data)

    capacity = width * height * 3

    if len(bits) > capacity:
        raise ValueError(
            f"File too large. Capacity: {capacity} bits"
        )

    index = 0

    for y in range(height):
        for x in range(width):

            pixel = pixels[x, y]

            if isinstance(pixel, tuple):
                r, g, b = pixel
            else:
                r = g = b = int(pixel)

            channels = [r, g, b]

            for c in range(3):

                if index < len(bits):

                    channels[c] = (
                        channels[c] & ~1
                    ) | int(bits[index])

                    index += 1

            pixels[x, y] = tuple(channels)

            if index >= len(bits):

                capacity_used = round(
                    (len(bits) / capacity) * 100,
                    2
                )

                return img, capacity_used

    capacity_used = round(
        (len(bits) / capacity) * 100,
        2
    )

    return img, capacity_used


#  LSB DECODE 
def decode_lsb(
    image: Image.Image
) -> bytes:

    img = image.convert("RGB")

    pixels = img.load()
    assert pixels is not None

    width, height = img.size

    bits = ""

    for y in range(height):
        for x in range(width):

            pixel = pixels[x, y]

            if isinstance(pixel, tuple):
                r, g, b = pixel
            else:
                r = g = b = int(pixel)

            bits += str(r & 1)
            bits += str(g & 1)
            bits += str(b & 1)

            if len(bits) >= 32:

                length_bits = bits[:32]

                length_bytes = bits_to_bytes(
                    length_bits
                )

                data_len = struct.unpack(
                    ">I",
                    length_bytes
                )[0]

                total_bits = 32 + data_len * 8

                if len(bits) >= total_bits:

                    secret_bits = bits[
                        32:total_bits
                    ]

                    return bits_to_bytes(
                        secret_bits
                    )

    raise ValueError(
        "No hidden data found."
    )


# FILE CHECK 
def allowed_image(filename: str) -> bool:

    allowed = {
        "png",
        "jpg",
        "jpeg",
        "bmp"
    }

    return (
        "." in filename and
        filename.rsplit(".", 1)[1].lower()
        in allowed
    )


def safe_filename(filename: str) -> str:

    filename = os.path.basename(filename)

    return (
        filename
        .encode("utf-8", errors="ignore")
        .decode("utf-8")
        .replace(" ", "_")
    )


# MAIN ROUTE
@app.route("/", methods=["GET", "POST"])
def index():

    data = {}

    if request.method == "POST":

        action = request.form.get("action")

        secret_type = request.form.get(
            "secret_type",
            "text"
        )

        password = request.form.get(
            "password",
            ""
        )

        image_file = request.files.get(
            "image"
        )

        if (
            not image_file or
            image_file.filename == ""
        ):

            data = {
                "error": "Please upload image."
            }

            return render_template(
                "index.html",
                data=data
            )

        filename = image_file.filename or ""

        if not allowed_image(
            filename
        ):

            data = {
                "error":
                "Only PNG/JPG/JPEG/BMP supported."
            }

            return render_template(
                "index.html",
                data=data
            )

        if not password:

            data = {
                "error":
                "AES password required."
            }

            return render_template(
                "index.html",
                data=data
            )

        uid = str(uuid.uuid4())

        original_path = os.path.join(
            UPLOAD_FOLDER,
            f"original_{uid}.png"
        )

        image = Image.open(
            image_file.stream
        ).convert("RGB")

        image.save(original_path)

        # ENCODE 
        if action == "encode":

            try:

                # ZIP FILE
                if secret_type == "zip":

                    zip_file = request.files.get(
                        "secret_file"
                    )

                    if (
                        not zip_file or
                        not zip_file.filename
                    ):

                        data = {
                            "error":
                            "Please upload ZIP file."
                        }

                        return render_template(
                            "index.html",
                            data=data
                        )

                    if not zip_file.filename.lower().endswith(".zip"):

                        data = {
                            "error":
                            "Only ZIP file supported."
                        }

                        return render_template(
                            "index.html",
                            data=data
                        )

                    raw_secret = zip_file.read()

                    original_secret_name = safe_filename(
                        zip_file.filename or ""
                    )

                    payload = create_payload(
                        raw_secret,
                        "zip",
                        original_secret_name
                    )

                # TEXT MESSAGE
                else:

                    secret_text = request.form.get(
                        "secret",
                        ""
                    )

                    if not secret_text:

                        data = {
                            "error":
                            "Secret text required."
                        }

                        return render_template(
                            "index.html",
                            data=data
                        )

                    payload = create_payload(
                        secret_text.encode("utf-8"),
                        "text",
                        "secret_message.txt"
                    )

                encrypted_payload = encrypt_bytes(
                    payload,
                    password
                )

                encoded_img, capacity_used = encode_lsb(
                    image,
                    encrypted_payload
                )

                encoded_path = os.path.join(
                    UPLOAD_FOLDER,
                    f"encoded_{uid}.png"
                )

                encoded_img.save(
                    encoded_path,
                    "PNG"
                )

                data = {
                    "success": True,
                    "original": "/" + original_path,
                    "encoded": "/" + encoded_path,
                    "download": "/" + encoded_path,
                    "width": image.size[0],
                    "height": image.size[1],
                    "secret_type": secret_type.upper(),
                    "hidden_size": len(encrypted_payload),
                    "capacity_used": capacity_used,
                    "encoding":
                    "AES-256 + LSB + ZIP Support"
                }

            except Exception as e:

                data = {
                    "error": str(e)
                }

        #  DECODE
        elif action == "decode":

            try:

                encrypted_payload = decode_lsb(
                    image
                )

                decrypted_payload = decrypt_bytes(
                    encrypted_payload,
                    password
                )

                file_type, filename, secret_data = parse_payload(
                    decrypted_payload
                )

                # TEXT
                if file_type == "text":

                    decoded_text = secret_data.decode(
                        "utf-8",
                        errors="ignore"
                    )

                    data = {
                        "decoded": decoded_text,
                        "original":
                        "/" + original_path,
                        "width":
                        image.size[0],
                        "height":
                        image.size[1],
                        "file_type":
                        "TEXT"
                    }

                # ZIP
                elif file_type == "zip":

                    output_name = (
                        f"decoded_{uid}_"
                        f"{safe_filename(filename)}"
                    )

                    output_path = os.path.join(
                        OUTPUT_FOLDER,
                        output_name
                    )

                    with open(
                        output_path,
                        "wb"
                    ) as f:

                        f.write(secret_data)

                    data = {
                        "decoded_file":
                        url_for(
                            "download_file",
                            filename=output_name
                        ),

                        "decoded_filename":
                        output_name,

                        "original":
                        "/" + original_path,

                        "width":
                        image.size[0],

                        "height":
                        image.size[1],

                        "file_type":
                        "ZIP"
                    }

                else:

                    data = {
                        "error":
                        "Unknown hidden file type."
                    }

            except Exception:

                data = {
                    "error":
                    "Wrong password or corrupted image."
                }

    return render_template(
        "index.html",
        data=data
    )


if __name__ == "__main__":
    app.run(debug=True)