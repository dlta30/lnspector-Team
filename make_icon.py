from PIL import Image, ImageDraw, ImageFont

# Match the public 3EN website favicon: black rounded tile, red accents, white wordmark.
SIZE = 256
SCALE = 4
N = SIZE * SCALE
im = Image.new("RGBA", (N, N), (8, 9, 13, 255))
d = ImageDraw.Draw(im)

def box(coords):
    return tuple(int(v * SCALE) for v in coords)

d.rounded_rectangle(box((2, 2, 62, 62)), radius=12*SCALE,
                    fill=(8, 9, 13, 255), outline=(143, 24, 53, 255), width=2*SCALE)

# Subtle red gradient accents, matching the website mark.
for x in range(9, 56):
    t = (x - 9) / 47
    color = (int(255 - 70*t), int(83 - 65*t), int(109 - 59*t), 255)
    d.line((x*SCALE, 18*SCALE, (x+0.01)*SCALE, 18*SCALE), fill=color, width=3*SCALE)
d.line(box((17, 52, 47, 52)), fill=(220, 24, 60, 255), width=3*SCALE)

font = None
for p in ("C:/Windows/Fonts/arialbd.ttf", "C:/Windows/Fonts/seguisb.ttf",
          "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"):
    try:
        font = ImageFont.truetype(p, 24*SCALE)
        break
    except OSError:
        pass
if font is None:
    font = ImageFont.load_default()

word = "3EN"
bbox = d.textbbox((0, 0), word, font=font)
x = (N - (bbox[2] - bbox[0])) / 2 - bbox[0]
y = 30*SCALE - (bbox[3] - bbox[1]) / 2 - bbox[1]
d.text((x, y), word, font=font, fill=(255, 255, 255, 255))

im = im.resize((SIZE, SIZE), Image.Resampling.LANCZOS)
im.save("3en.png", "PNG")
im.save("3en.ico", "ICO", sizes=[(256,256),(128,128),(64,64),(48,48),(32,32),(16,16)])
