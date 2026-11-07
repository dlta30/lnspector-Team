from PIL import Image, ImageDraw, ImageFont

# 3EN INSPECT app icon — intentionally matches static/favicon.svg on the website.
SIZE = 512
SCALE = 4
N = SIZE * SCALE
im = Image.new("RGBA", (N, N), "#08090d")
draw = ImageDraw.Draw(im)

def p(value):
    return int(value * SCALE)

# Website-matched rounded square and thin burgundy outline.
draw.rounded_rectangle(
    (p(2), p(2), p(62), p(62)),
    radius=p(12),
    outline="#8f1835",
    width=p(2),
)

# Red gradient strokes matching the website favicon.
def gradient_line(x1, y, x2, color_left="#ff536d", color_right="#b50932", width=3):
    from PIL import ImageColor
    c1 = ImageColor.getrgb(color_left)
    c2 = ImageColor.getrgb(color_right)
    length = max(1, p(x2 - x1))
    for offset in range(length + 1):
        t = offset / length
        color = tuple(round(c1[i] * (1 - t) + c2[i] * t) for i in range(3))
        x = p(x1) + offset
        draw.line((x, p(y), x, p(y)), fill=color, width=p(width))
    draw.line((p(x1), p(y), p(x2), p(y)), fill=color_right, width=p(width), joint="curve")

gradient_line(9, 18, 55, width=3)
gradient_line(17, 52, 47, width=2.5)

# Strong centered 3EN wordmark, same proportions and clean white treatment as the site.
font = None
font_candidates = [
    "C:/Windows/Fonts/arialbd.ttf",
    "C:/Windows/Fonts/seguisb.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
]
for candidate in font_candidates:
    try:
        font = ImageFont.truetype(candidate, p(24))
        break
    except OSError:
        continue
if font is None:
    font = ImageFont.load_default()

text = "3EN"
bbox = draw.textbbox((0, 0), text, font=font, stroke_width=0)
tw = bbox[2] - bbox[0]
th = bbox[3] - bbox[1]
x = (N - tw) // 2 - bbox[0]
y = p(32) - (th // 2) - bbox[1] + p(1)
draw.text((x, y), text, font=font, fill="#ffffff")

im = im.resize((SIZE, SIZE), Image.Resampling.LANCZOS)
im.save("3en.png", optimize=True)
im.save(
    "3en.ico",
    format="ICO",
    sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
)
print("Generated website-matched 3EN INSPECT icons: 3en.png, 3en.ico")
