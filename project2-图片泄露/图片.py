import cv2
import numpy as np
import random
import matplotlib.pyplot as plt
from PIL import Image, ImageEnhance

# 解决中文显示问题：指定中文字体 + 处理负号
plt.rcParams['font.sans-serif'] = 'SimHei'  # 替换为系统支持的中文字体（如 SimHei、Microsoft YaHei）
plt.rcParams['axes.unicode_minus'] = False  # 避免负号显示为方块

# 若使用无界面后端（Agg），需确保最终用 savefig 保存；若要交互显示，注释下面一行并确保 Tkinter 依赖完整
import matplotlib
matplotlib.use('Agg')  # 保持无界面后端（按需注释切换）


class WatermarkingSystem:
    def __init__(self, watermark_size=(32, 32)):
        self.watermark_size = watermark_size
        self.seed = 42
        random.seed(self.seed)

    def generate_watermark(self, text=None):
        if text:
            watermark = np.zeros(self.watermark_size, dtype=np.uint8)
            cv2.putText(watermark, text, (5, 20),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255), 1)
            _, watermark = cv2.threshold(watermark, 127, 255, cv2.THRESH_BINARY)
            return watermark / 255
        else:
            return np.random.randint(0, 2, self.watermark_size).astype(np.float32)

    def embed_watermark(self, image_path, watermark, output_path=None):
        image = cv2.imread(image_path)
        if image is None:
            raise ValueError(f"无法读取图像: {image_path}")

        ycrcb_image = cv2.cvtColor(image, cv2.COLOR_BGR2YCrCb)
        y_channel = ycrcb_image[:, :, 0].astype(np.float32)

        h, w = y_channel.shape
        watermark_h, watermark_w = self.watermark_size

        block_size = 8
        alpha = 0.03

        random.seed(self.seed)
        positions = [(i, j) for i in range(0, h - block_size, block_size)
                     for j in range(0, w - block_size, block_size)]
        random.shuffle(positions)
        selected_positions = positions[:watermark_h * watermark_w]

        watermarked_y = y_channel.copy()

        for idx, (i, j) in enumerate(selected_positions):
            block = watermarked_y[i:i + block_size, j:j + block_size]
            dct_block = cv2.dct(block)

            wm_row = idx // watermark_w
            wm_col = idx % watermark_w

            dct_block[5, 5] += alpha * (1 if watermark[wm_row, wm_col] > 0.5 else -1)

            watermarked_block = cv2.idct(dct_block)
            watermarked_y[i:i + block_size, j:j + block_size] = watermarked_block

        ycrcb_image[:, :, 0] = watermarked_y.astype(np.uint8)
        watermarked_image = cv2.cvtColor(ycrcb_image, cv2.COLOR_YCrCb2BGR)

        if output_path:
            cv2.imwrite(output_path, watermarked_image)

        return watermarked_image

    def extract_watermark(self, original_image_path, watermarked_image_path):
        original = cv2.imread(original_image_path)
        watermarked = cv2.imread(watermarked_image_path)

        if original is None or watermarked is None:
            raise ValueError("无法读取原始图像或含水印图像")

        original_ycrcb = cv2.cvtColor(original, cv2.COLOR_BGR2YCrCb)
        watermarked_ycrcb = cv2.cvtColor(watermarked, cv2.COLOR_BGR2YCrCb)

        original_y = original_ycrcb[:, :, 0].astype(np.float32)
        watermarked_y = watermarked_ycrcb[:, :, 0].astype(np.float32)

        h, w = original_y.shape
        watermark_h, watermark_w = self.watermark_size

        extracted_watermark = np.zeros(self.watermark_size, dtype=np.float32)

        block_size = 8

        random.seed(self.seed)
        positions = [(i, j) for i in range(0, h - block_size, block_size)
                     for j in range(0, w - block_size, block_size)]
        random.shuffle(positions)
        selected_positions = positions[:watermark_h * watermark_w]

        for idx, (i, j) in enumerate(selected_positions):
            original_block = original_y[i:i + block_size, j:j + block_size]
            watermarked_block = watermarked_y[i:i + block_size, j:j + block_size]

            dct_original = cv2.dct(original_block)
            dct_watermarked = cv2.dct(watermarked_block)

            wm_row = idx // watermark_w
            wm_col = idx % watermark_w

            diff = dct_watermarked[5, 5] - dct_original[5, 5]
            extracted_watermark[wm_row, wm_col] = 1 if diff > 0 else 0

        return extracted_watermark

    def apply_attack(self, image, attack_type, severity=1):
        attacked = image.copy()

        if attack_type == 'flip':
            if severity % 2 == 0:
                attacked = cv2.flip(attacked, 1)
            else:
                attacked = cv2.flip(attacked, 0)

        elif attack_type == 'rotate':
            angle = 15 * severity
            h, w = attacked.shape[:2]
            center = (w // 2, h // 2)
            M = cv2.getRotationMatrix2D(center, angle, 1.0)
            attacked = cv2.warpAffine(attacked, M, (w, h))

        elif attack_type == 'crop':
            h, w = attacked.shape[:2]
            crop_size = int(min(h, w) * (1 - 0.1 * severity))
            start_x = (w - crop_size) // 2
            start_y = (h - crop_size) // 2
            attacked = attacked[start_y:start_y + crop_size, start_x:start_x + crop_size]
            attacked = cv2.resize(attacked, (w, h))

        elif attack_type == 'resize':
            scale = 1 - 0.15 * severity
            if scale < 0.3:
                scale = 0.3
            h, w = attacked.shape[:2]
            new_size = (int(w * scale), int(h * scale))
            attacked = cv2.resize(attacked, new_size)
            attacked = cv2.resize(attacked, (w, h))

        elif attack_type == 'noise':
            mean = 0
            var = 10 * severity
            sigma = var ** 0.5
            gauss = np.random.normal(mean, sigma, attacked.shape)
            noisy = attacked + gauss
            attacked = np.clip(noisy, 0, 255).astype(np.uint8)

        elif attack_type == 'blur':
            ksize = 2 * severity + 1
            attacked = cv2.GaussianBlur(attacked, (ksize, ksize), 0)

        elif attack_type == 'contrast':
            factor = 1.0 + (severity - 3) * 0.3
            if factor <= 0:
                factor = 0.1

            img_pil = Image.fromarray(cv2.cvtColor(attacked, cv2.COLOR_BGR2RGB))
            enhancer = ImageEnhance.Contrast(img_pil)
            img_pil = enhancer.enhance(factor)
            attacked = cv2.cvtColor(np.array(img_pil), cv2.COLOR_RGB2BGR)

        else:
            raise ValueError(f"不支持的攻击类型: {attack_type}")

        return attacked

    def calculate_similarity(self, original_watermark, extracted_watermark):
        match = np.sum(original_watermark == extracted_watermark)
        total = original_watermark.size
        return (match / total) * 100


def demo():
    watermark_system = WatermarkingSystem(watermark_size=(32, 32))

    original_watermark = watermark_system.generate_watermark("Confidential")

    try:
        watermarked_image = watermark_system.embed_watermark(
            "5114.png",
            original_watermark,
            "watermarked_image.png"
        )
        print("水印嵌入成功")
    except Exception as e:
        print(f"水印嵌入失败: {e}")
        return

    try:
        extracted_watermark = watermark_system.extract_watermark(
            "5114.png",
            "watermarked_image.png"
        )
        similarity = watermark_system.calculate_similarity(original_watermark, extracted_watermark)
        print(f"原始图像提取水印相似度: {similarity:.2f}%")
    except Exception as e:
        print(f"水印提取失败: {e}")
        return

    attacks = [
        ('flip', 1),
        ('rotate', 2),
        ('crop', 2),
        ('resize', 2),
        ('noise', 2),
        ('blur', 2),
        ('contrast', 4)
    ]

    print("\n鲁棒性测试结果:")
    for attack_type, severity in attacks:
        attacked_image = watermark_system.apply_attack(watermarked_image, attack_type, severity)
        cv2.imwrite(f"attacked_{attack_type}.png", attacked_image)

        try:
            cv2.imwrite("temp_attacked.png", attacked_image)

            extracted = watermark_system.extract_watermark(
                "5114.png",
                "temp_attacked.png"
            )

            similarity = watermark_system.calculate_similarity(original_watermark, extracted)
            print(f"{attack_type} (强度 {severity}) - 相似度: {similarity:.2f}%")
        except Exception as e:
            print(f"{attack_type} 测试失败: {e}")

    # 绘图逻辑调整：用 savefig 保存而不是 show（因 Agg 后端无交互）
    plt.figure(figsize=(15, 10))

    original_img = cv2.imread("5114.png")
    original_img_rgb = cv2.cvtColor(original_img, cv2.COLOR_BGR2RGB)
    plt.subplot(3, 3, 1)
    plt.imshow(original_img_rgb)
    plt.title("原始图像")
    plt.axis('off')

    plt.subplot(3, 3, 2)
    plt.imshow(original_watermark, cmap='gray')
    plt.title("原始水印")
    plt.axis('off')

    watermarked_img_rgb = cv2.cvtColor(watermarked_image, cv2.COLOR_BGR2RGB)
    plt.subplot(3, 3, 3)
    plt.imshow(watermarked_img_rgb)
    plt.title("含水印图像")
    plt.axis('off')

    for i, (attack_type, severity) in enumerate(attacks[:6]):
        attacked_img = cv2.imread(f"attacked_{attack_type}.png")
        attacked_img_rgb = cv2.cvtColor(attacked_img, cv2.COLOR_BGR2RGB)
        plt.subplot(3, 3, i + 4)
        plt.imshow(attacked_img_rgb)
        plt.title(f"{attack_type} 攻击")
        plt.axis('off')

    plt.tight_layout()
    # 替换 plt.show() 为保存图片
    plt.savefig("watermark_demo.png")
    print("结果已保存为 watermark_demo.png")


if __name__ == "__main__":
    try:
        img = cv2.imread("5114.png")
        if img is None:
            raise FileNotFoundError
    except FileNotFoundError:
        print("创建测试图像 5114.png")
        img = np.ones((512, 512, 3), dtype=np.uint8) * 240
        cv2.putText(img, "Test Image", (150, 250),
                    cv2.FONT_HERSHEY_SIMPLEX, 1.5, (0, 0, 0), 3)
        cv2.imwrite("5114.png", img)

    demo()