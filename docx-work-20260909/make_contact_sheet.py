from pathlib import Path
import sys
from PIL import Image, ImageDraw, ImageFont

page_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(r"C:\Users\vic\Documents\agent-scan-json\docx-work-20260909\qa-pages")
paths = sorted(page_dir.glob("page-*.png"))
font = ImageFont.truetype(r"C:\Windows\Fonts\msyh.ttc", 24)
thumb_w = 420
gap = 26
label_h = 40
thumbs = []
for path in paths:
    image = Image.open(path).convert("RGB")
    thumb_h = round(image.height * thumb_w / image.width)
    image = image.resize((thumb_w, thumb_h))
    thumbs.append((path, image))

cols = 3
rows = (len(thumbs) + cols - 1) // cols
cell_h = max(img.height for _, img in thumbs) + label_h
sheet = Image.new("RGB", (cols * thumb_w + (cols + 1) * gap, rows * cell_h + (rows + 1) * gap), "#d9dde3")
draw = ImageDraw.Draw(sheet)
for index, (path, image) in enumerate(thumbs):
    col, row = index % cols, index // cols
    x = gap + col * (thumb_w + gap)
    y = gap + row * (cell_h + gap)
    sheet.paste(image, (x, y + label_h))
    label = f"第 {index + 1} 页"
    draw.text((x, y + 4), label, fill="#1f4e78", font=font)

sheet.save(page_dir / "contact-sheet.png", quality=94)
