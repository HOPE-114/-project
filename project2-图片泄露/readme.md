# 基于数字水印的图片泄露检测

基于数字水印的图片泄露检测，支持文本/随机水印的嵌入、提取和抗攻击测试。


## 功能特性
✅ **核心功能**  
- 文本水印/随机水印生成  
- 基于种子的随机块选择策略  
- 水印提取与相似度计算  

🛡️ **抗攻击测试**  
支持 7 种攻击类型的鲁棒性测试：
1. 翻转攻击 (`flip`)  
2. 旋转攻击 (`rotate`)  
3. 裁剪攻击 (`crop`)  
4. 缩放攻击 (`resize`)  
5. 噪声攻击 (`noise`)  
6. 模糊攻击 (`blur`)  
7. 对比度攻击 (`contrast`)

---

## 快速开始
### 1. 安装依赖
```bash
pip install opencv-python numpy matplotlib pillow
```

### 2. 基础使用
```python
from watermark_system import WatermarkingSystem

# 初始化系统
wm_system = WatermarkingSystem(watermark_size=(32, 32))

# 生成文字水印
watermark = wm_system.generate_watermark("Secret")

# 嵌入水印
watermarked_img = wm_system.embed_watermark(
    "input.png", 
    watermark,
    "output.png"
)

# 提取水印
extracted = wm_system.extract_watermark("input.png", "output.png")

# 计算相似度
similarity = wm_system.calculate_similarity(watermark, extracted)
print(f"相似度: {similarity:.2f}%")
```

---

## API 说明
### `WatermarkingSystem` 类
| 方法 | 参数 | 返回 | 说明 |
|------|------|------|------|
| `generate_watermark` | `text: str = None` | `np.ndarray` | 生成文本/随机二值水印矩阵 |
| `embed_watermark` | `image_path: str`, `watermark: np.ndarray`, `output_path: str = None` | `np.ndarray` | 将水印嵌入图像Y通道的DCT域 |
| `extract_watermark` | `original_path: str`, `watermarked_path: str` | `np.ndarray` | 从含水印图像中提取水印 |
| `apply_attack` | `image: np.ndarray`, `attack_type: str`, `severity: int = 1` | `np.ndarray` | 对图像施加指定攻击 |
| `calculate_similarity` | `original_wm: np.ndarray`, `extracted_wm: np.ndarray` | `float` | 计算两水印的像素级相似度 |

---

## 攻击类型
| 类型 | 参数说明 | 强度影响 |
|------|----------|----------|
| `flip` | 1=垂直翻转, 2=水平翻转 | 翻转方向 |
| `rotate` | 旋转角度=15×强度 | 角度增大 |
| `crop` | 裁剪中心区域(1-0.1×强度) | 裁剪范围扩大 |
| `resize` | 缩放比例=1-0.15×强度 | 缩放程度增加 |
| `noise` | 高斯噪声方差=10×强度 | 噪声增强 |
| `blur` | 高斯核大小=2×强度+1 | 模糊程度增加 |
| `contrast` | 对比度系数=1+(强度-3)×0.3 | 对比度变化加剧 |

---

## 示例结果
![image](/project2-图片泄露/watermark.png)

---
结果说明水印正常嵌入图像，且从未受攻击的原始含水印图中提取时，和原始水印完全匹配（100% 相似），基础功能没问题。resize（缩放）和 contrast（对比度）攻击下，水印极稳定（接近 100%）；rotate（旋转）和 crop（裁剪）对水印影响最大（69%~70%）；整体能抵御常见图像处理攻击，适配实际场景。
## 实现原理
### 水印嵌入流程
1. 转换到 YCrCb 色彩空间，提取亮度通道 (Y)  
2. 将图像分块 (8×8)，随机选择嵌入位置  
3. 对每个块进行 DCT 变换  
4. 在中频系数 (5,5) 处修改值：  
   - 水印像素=1 → 增加α值  
   - 水印像素=0 → 减少α值  
5. 逆DCT后合并通道得到含水印图像  

### 水印提取流程
1. 计算原始图像与含水印图像的Y通道差值  
2. 在相同位置提取DCT系数差异  
3. 差值>0 → 1，否则→0  

---



