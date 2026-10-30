from PIL import Image, ImageDraw, ImageFont, ImageFilter

SIZE = 256
SCALE = 3
canvas_size = SIZE * SCALE

# Deep black background with a subtle red glow behind the emblem.
image = Image.new("RGBA", (canvas_size, canvas_size), (5, 5, 8, 255))
glow = Image.new("RGBA", image.size, (0, 0, 0, 0))
glow_draw = ImageDraw.Draw(glow)
glow_draw.ellipse((28*SCALE, 28*SCALE, 228*SCALE, 228*SCALE),
                  fill=(150, 0, 18, 105))
glow = glow.filter(ImageFilter.GaussianBlur(24*SCALE))
image = Image.alpha_composite(image, glow)
draw = ImageDraw.Draw(image)

# Layered black-and-red badge with a crisp red outer ring.
draw.ellipse((10*SCALE, 10*SCALE, 246*SCALE, 246*SCALE),
             fill=(8, 8, 12, 255), outline=(190, 12, 35, 255), width=7*SCALE)
draw.ellipse((23*SCALE, 23*SCALE, 233*SCALE, 233*SCALE),
             outline=(75, 12, 23, 255), width=2*SCALE)
draw.arc((31*SCALE, 31*SCALE, 225*SCALE, 225*SCALE),
         start=205, end=335, fill=(245, 35, 55, 255), width=3*SCALE)

font = None
for candidate in (
    "C:/Windows/Fonts/arialbd.ttf",
    "C:/Windows/Fonts/seguisb.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
):
    try:
        font = ImageFont.truetype(candidate, 78*SCALE)
        break
    except OSError:
        pass
if font is None:
    font = ImageFont.load_default()

label = "3EN"
bbox = draw.textbbox((0, 0), label, font=font, stroke_width=1*SCALE)
x = (canvas_size - (bbox[2] - bbox[0])) / 2 - bbox[0]
y = (canvas_size - (bbox[3] - bbox[1])) / 2 - bbox[1] - 3*SCALE

# Dark offset gives the lettering depth; red face keeps the mark readable.
draw.text((x + 2*SCALE, y + 4*SCALE), label, font=font,
          fill=(65, 0, 12, 255), stroke_width=2*SCALE,
          stroke_fill=(110, 5, 22, 255))
draw.text((x, y), label, font=font, fill=(245, 238, 240, 255),
          stroke_width=2*SCALE, stroke_fill=(220, 18, 42, 255))

image = image.resize((SIZE, SIZE), Image.Resampling.LANCZOS)
image.save("3en.ico", format="ICO",
           sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])
