from PIL import Image, ImageDraw, ImageFont, ImageFilter

# Premium 3EN identity: bold monogram, shield geometry and restrained red glow.
SIZE = 512
SCALE = 3
N = SIZE * SCALE
im = Image.new("RGBA", (N, N), (6, 7, 12, 255))
draw = ImageDraw.Draw(im)

def p(v):
    return int(v * SCALE)

def poly(points, fill, outline=None, width=1):
    pts = [(p(x), p(y)) for x, y in points]
    draw.polygon(pts, fill=fill)
    if outline:
        draw.line(pts + [pts[0]], fill=outline, width=p(width), joint="curve")

# Deep red atmospheric halo behind the shield.
glow = Image.new("RGBA", im.size, (0, 0, 0, 0))
gd = ImageDraw.Draw(glow)
gd.ellipse((p(65), p(45), p(447), p(455)), fill=(210, 5, 42, 105))
glow = glow.filter(ImageFilter.GaussianBlur(p(44)))
im = Image.alpha_composite(im, glow)
draw = ImageDraw.Draw(im)

# Layered shield silhouette with a crisp red edge.
outer = [(256, 24), (438, 91), (420, 292), (369, 388), (256, 476),
         (143, 388), (92, 292), (74, 91)]
inner = [(256, 48), (415, 107), (398, 285), (350, 369), (256, 442),
         (162, 369), (114, 285), (97, 107)]
poly(outer, (13, 10, 17, 255), (235, 28, 62, 255), 8)
poly(inner, (8, 10, 16, 255), (104, 18, 42, 255), 3)

# Subtle top/bottom angular cuts create a custom esports/security mark.
poly([(111, 115), (170, 137), (170, 147), (111, 128)], (255, 48, 83, 210))
poly([(401, 115), (342, 137), (342, 147), (401, 128)], (255, 48, 83, 210))
poly([(150, 355), (190, 382), (178, 391), (137, 362)], (153, 20, 48, 255))
poly([(362, 355), (322, 382), (334, 391), (375, 362)], (153, 20, 48, 255))

# Strong, clean 3EN wordmark.
font = None
for path in ("C:/Windows/Fonts/arialbd.ttf", "C:/Windows/Fonts/seguisb.ttf",
             "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"):
    try:
        font = ImageFont.truetype(path, p(132))
        break
    except OSError:
        pass
if font is None:
    font = ImageFont.load_default()

word = "3EN"
bbox = draw.textbbox((0, 0), word, font=font, stroke_width=p(1))
tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
x = (N - tw) // 2 - bbox[0]
y = p(194) - bbox[1]
draw.text((x, y), word, font=font, fill=(255, 249, 251, 255),
          stroke_width=p(1), stroke_fill=(255, 255, 255, 255))

# Red divider and small INSPECT wordmark.
draw.rounded_rectangle((p(158), p(345), p(354), p(352)), radius=p(4),
                       fill=(255, 38, 75, 255))
small = None
for path in ("C:/Windows/Fonts/arialbd.ttf", "C:/Windows/Fonts/seguisb.ttf",
             "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"):
    try:
        small = ImageFont.truetype(path, p(29))
        break
    except OSError:
        pass
if small:
    label = "INSPECT"
    b = draw.textbbox((0, 0), label, font=small)
    draw.text(((N-(b[2]-b[0]))//2, p(365)-b[1]), label, font=small,
              fill=(224, 225, 233, 255))

# Final high-quality raster outputs used by the UI and Windows executable.
im = im.resize((SIZE, SIZE), Image.Resampling.LANCZOS)
im.save("3en.png", "PNG", optimize=True)
im.save("3en.ico", "ICO", sizes=[(256,256),(128,128),(64,64),(48,48),(32,32),(16,16)])
