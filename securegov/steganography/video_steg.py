import cv2
import numpy as np
import os
import subprocess
import shutil


class VideoSteganography:
    """
    Video Steganography menggunakan metode LSB.

    Fitur:
    - Menyisipkan pesan pada channel Blue.
    - Menggunakan codec FFV1 (lossless).
    - Memproses video per frame.
    - Mempertahankan audio asli menggunakan FFmpeg.
    """

    @staticmethod
    def _text_to_bits(message: str) -> np.ndarray:
        message_bytes = message.encode("utf-8")

        # Header 4 byte untuk menyimpan panjang pesan
        header = len(message_bytes).to_bytes(
            4, byteorder="little"
        )

        data = header + message_bytes

        return np.unpackbits(
            np.frombuffer(data, dtype=np.uint8)
        )

    @staticmethod
    def _bits_to_text(bits: np.ndarray) -> str:
        data = np.packbits(bits).tobytes()

        message_length = int.from_bytes(
            data[:4], byteorder="little"
        )

        message_bytes = data[4:4 + message_length]

        return message_bytes.decode("utf-8")

    def embed(
        self,
        cover_path: str,
        message: str,
        output_path: str,
        lossless_codec: str = "FFV1"
    ) -> str:

        # ==========================================
        # 1. VALIDASI INPUT
        # ==========================================

        if not os.path.isfile(cover_path):
            raise FileNotFoundError(
                f"Video input tidak ditemukan: {cover_path}"
            )

        if os.path.abspath(cover_path) == os.path.abspath(output_path):
            raise ValueError(
                "Output tidak boleh menimpa video asli."
            )

        ffmpeg_path = shutil.which("ffmpeg")

        if ffmpeg_path is None:
            raise RuntimeError(
                "FFmpeg belum terpasang atau belum masuk PATH."
            )

        # Pastikan output menggunakan MKV
        if not output_path.lower().endswith(".mkv"):
            output_path = (
                os.path.splitext(output_path)[0] + ".mkv"
            )

        output_dir = os.path.dirname(
            os.path.abspath(output_path)
        )

        os.makedirs(output_dir, exist_ok=True)

        temp_video = (
            os.path.splitext(output_path)[0] + "_temp.mkv"
        )

        # ==========================================
        # 2. MEMBUKA VIDEO
        # ==========================================

        cap = cv2.VideoCapture(cover_path)

        if not cap.isOpened():
            raise ValueError("Gagal membuka video input.")

        fps = cap.get(cv2.CAP_PROP_FPS)
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        frame_count = int(
            cap.get(cv2.CAP_PROP_FRAME_COUNT)
        )

        if fps <= 0 or width <= 0 or height <= 0:
            cap.release()
            raise ValueError(
                "Informasi video tidak valid."
            )

        if frame_count <= 0:
            cap.release()
            raise ValueError(
                "Jumlah frame video tidak dapat dibaca."
            )

        # ==========================================
        # 3. MENGHITUNG KAPASITAS
        # ==========================================

        bits = self._text_to_bits(message)

        total_capacity = frame_count * width * height

        if len(bits) > total_capacity:
            cap.release()

            max_bytes = max(
                0, (total_capacity - 32) // 8
            )

            raise ValueError(
                f"Pesan terlalu besar. "
                f"Kapasitas maksimum sekitar {max_bytes} byte."
            )

        # ==========================================
        # 4. MENYIAPKAN VIDEO WRITER
        # ==========================================

        fourcc = cv2.VideoWriter_fourcc(
            *lossless_codec
        )

        writer = cv2.VideoWriter(
            temp_video,
            fourcc,
            fps,
            (width, height)
        )

        if not writer.isOpened():
            cap.release()
            writer.release()

            raise RuntimeError(
                "Gagal membuat video FFV1. "
                "Periksa dukungan codec OpenCV."
            )

        # ==========================================
        # 5. PROSES PENYISIPAN LSB
        # ==========================================

        bit_index = 0

        try:
            while True:
                ret, frame = cap.read()

                if not ret:
                    break

                blue = frame[:, :, 0].reshape(-1)

                remaining = len(bits) - bit_index

                if remaining > 0:
                    count = min(
                        len(blue), remaining
                    )

                    frame_bits = bits[
                        bit_index:bit_index + count
                    ].astype(np.uint8)

                    # Menyisipkan bit ke LSB channel Blue
                    blue[:count] = (
                        (blue[:count] & 0xFE)
                        | frame_bits
                    )

                    bit_index += count

                writer.write(frame)

        finally:
            cap.release()
            writer.release()

        if bit_index < len(bits):
            if os.path.exists(temp_video):
                os.remove(temp_video)

            raise RuntimeError(
                "Gagal menyisipkan seluruh pesan ke video."
            )

        # ==========================================
        # 6. MENGGABUNGKAN AUDIO ASLI
        # ==========================================

        try:
            command = [
                ffmpeg_path,
                "-y",

                # Input 0: video hasil steganografi
                "-i", temp_video,

                # Input 1: video asli yang memiliki audio
                "-i", cover_path,

                # Ambil video dari input pertama
                "-map", "0:v:0",

                # Ambil audio dari input kedua jika tersedia
                "-map", "1:a?",

                # Tidak melakukan encoding ulang
                "-c:v", "copy",
                "-c:a", "copy",

                # Pertahankan metadata
                "-map_metadata", "1",

                # Batasi output mengikuti durasi terpendek
                "-shortest",

                output_path
            ]

            result = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True
            )

            if not os.path.isfile(output_path):
                raise RuntimeError(
                    "File output tidak berhasil dibuat."
                )

            return output_path

        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                "FFmpeg gagal menggabungkan audio dan video.\n"
                + e.stderr[-3000:]
            ) from e

        finally:
            if os.path.exists(temp_video):
                os.remove(temp_video)

    def extract(self, stego_path: str) -> str:

        # ==========================================
        # 1. VALIDASI VIDEO
        # ==========================================

        if not os.path.isfile(stego_path):
            raise FileNotFoundError(
                f"Video tidak ditemukan: {stego_path}"
            )

        cap = cv2.VideoCapture(stego_path)

        if not cap.isOpened():
            raise ValueError(
                "Gagal membuka video steganografi."
            )

        width = int(
            cap.get(cv2.CAP_PROP_FRAME_WIDTH)
        )

        height = int(
            cap.get(cv2.CAP_PROP_FRAME_HEIGHT)
        )

        frame_count = int(
            cap.get(cv2.CAP_PROP_FRAME_COUNT)
        )

        total_capacity = (
            frame_count * width * height
        )

        if total_capacity < 32:
            cap.release()
            raise ValueError(
                "Kapasitas video terlalu kecil."
            )

        collected = []
        collected_count = 0
        required_bits = 32

        # ==========================================
        # 2. EKSTRAKSI HEADER DAN PESAN
        # ==========================================

        try:
            while collected_count < required_bits:

                ret, frame = cap.read()

                if not ret:
                    break

                blue = frame[:, :, 0].reshape(-1)

                # Mengambil bit paling rendah
                frame_bits = blue & 1

                collected.append(frame_bits)
                collected_count += len(frame_bits)

                # Setelah 32 bit tersedia, baca header
                if (
                    collected_count >= 32
                    and required_bits == 32
                ):

                    all_bits = np.concatenate(
                        collected
                    )

                    header_bytes = np.packbits(
                        all_bits[:32]
                    ).tobytes()

                    message_length = int.from_bytes(
                        header_bytes,
                        byteorder="little"
                    )

                    required_bits = (
                        32 + message_length * 8
                    )

                    if required_bits > total_capacity:
                        raise ValueError(
                            "Header tidak valid atau "
                            "pesan melebihi kapasitas video."
                        )

            if collected_count < required_bits:
                raise ValueError(
                    "Pesan tidak lengkap atau video rusak."
                )

            # ==========================================
            # 3. MENGEMBALIKAN PESAN
            # ==========================================

            all_bits = np.concatenate(collected)

            message_bits = all_bits[:required_bits]

            return self._bits_to_text(
                message_bits
            )

        finally:
            cap.release()