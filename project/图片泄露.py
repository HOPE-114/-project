import cv2
import numpy as np

def generate_watermark(shape, text='Watermark'):
    """
    生成简单的文字二值水印图像
    """
    wm = np.zeros(shape, dtype=np.uint8)
    font_scale = 3
    thickness = 5
    text_size, _ = cv2.getTextSize(text, cv2.FONT_HERSHEY_SIMPLEX, font_scale, thickness)
    text_x = (shape[1] - text_size[0]) // 2
    text_y = (shape[0] + text_size[1]) // 2
    cv2.putText(wm, text, (text_x, text_y), cv2.FONT_HERSHEY_SIMPLEX, font_scale, 255, thickness)
    return wm

def embed_watermark(image, watermark, alpha=0.2):
    """
    在图像中嵌入水印
    """
    # 确保水印尺寸与图像一致
    watermark_resized = cv2.resize(watermark, (image.shape[1], image.shape[0]))
    # 将水印叠加到原图（线性叠加）
    watermarked = cv2.addWeighted(image, 1, watermark_resized, alpha, 0)
    return watermarked

def extract_watermark(watermarked_img, original_img, threshold=0.05):
    """
    提取水印（通过差异检测）
    """
    diff = cv2.absdiff(watermarked_img, original_img).astype(np.float32) / 255
    # 超过阈值的像素点即为水印部分
    wm_mask = diff > threshold
    return wm_mask.astype(np.uint8) * 255

def apply_transformations(image):
    """
    对图片进行多种攻击变换，测试水印鲁棒性
    """
    # 1. 翻转
    flipped = cv2.flip(image, 1)
    # 2. 平移(10像素)
    M_translate = np.float32([[1, 0, 10], [0, 1, 10]])
    translated = cv2.warpAffine(image, M_translate, (image.shape[1], image.shape[0]))
    # 3. 对比度调节（增加1.5倍）
    contrast = cv2.convertScaleAbs(image, alpha=1.5, beta=0)
    return flipped, translated, contrast

if __name__ == "__main__":
    # 读取原始灰度图（确保替换为存在的图片路径）
    img = cv2.imread('your_image.jpg', cv2.IMREAD_GRAYSCALE)
    if img is None:
        print("请确保路径存在一张图片 'your_image.jpg'")
        exit()

    # 生成水印
    watermark = generate_watermark(img.shape, text='Watermark')
    # 嵌入水印
    watermarked_img = embed_watermark(img, watermark, alpha=0.2)
    cv2.imwrite('watermarked.jpg', watermarked_img)

    # 对水印图像进行多种攻击变换
    flipped_img, translated_img, contrast_img = apply_transformations(watermarked_img)

    # 提取水印（在不同攻击后）
    for idx, attack_img in enumerate([flipped_img, translated_img, contrast_img]):
        extracted = extract_watermark(attack_img, watermarked_img)
        cv2.imwrite(f'extracted_{idx}.png', extracted)
        # 展示
        cv2.imshow(f'Attack {idx+1}', attack_img)
        cv2.imshow(f'Extracted Watermark {idx+1}', extracted)

    cv2.waitKey(0)
    cv2.destroyAllWindows()