from PIL import Image, ImageDraw, ImageFont, ImageFilter

SIZE = 256
SCALE = 3
N = SIZE * SCALE
im = Image.new("RGBA", (N, N), (5, 5, 9, 255))
glow = Image.new("RGBA", im.size, (0, 0, 0, 0))
gd = ImageDraw.Draw(glow)
gd.ellipse((25*SCALE, 15*SCALE, 231*SCALE, 235*SCALE), fill=(220, 0, 35, 105))
im = Image.alpha_composite(im, glow.filter(ImageFilter.GaussianBlur(25*SCALE)))
d = ImageDraw.Draw(im)
d.rounded_rectangle((8*SCALE, 8*SCALE, 248*SCALE, 248*SCALE), radius=42*SCALE,
                    fill=(10, 8, 13, 255), outline=(245, 25, 55, 255), width=7*SCALE)
d.rounded_rectangle((20*SCALE, 20*SCALE, 236*SCALE, 236*SCALE), radius=34*SCALE,
                    outline=(105, 12, 30, 255), width=2*SCALE)
# Red eye emblem above the English brand name.
d.arc((48*SCALE, 35*SCALE, 208*SCALE, 117*SCALE), 200, 340, fill=(255, 60, 82, 255), width=5*SCALE)
d.arc((48*SCALE, 35*SCALE, 208*SCALE, 117*SCALE), 20, 160, fill=(255, 60, 82, 255), width=5*SCALE)
d.ellipse((91*SCALE, 48*SCALE, 165*SCALE, 104*SCALE), outline=(255, 70, 92, 255), width=4*SCALE)
d.ellipse((108*SCALE, 52*SCALE, 148*SCALE, 100*SCALE), fill=(235, 20, 48, 255))
d.ellipse((119*SCALE, 57*SCALE, 137*SCALE, 95*SCALE), fill=(8, 8, 12, 255))
d.ellipse((124*SCALE, 62*SCALE, 131*SCALE, 75*SCALE), fill=(255, 255, 255, 255))

def font(size):
    for p in ("C:/Windows/Fonts/arialbd.ttf", "C:/Windows/Fonts/seguisb.ttf",
              "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"):
        try:
            return ImageFont.truetype(p, size*SCALE)
        except OSError:
            pass
    return ImageFont.load_default()

def centered(text, y, f, fill):
    b = d.textbbox((0, 0), text, font=f)
    x = (N - (b[2]-b[0])) / 2 - b[0]
    d.text((x, y*SCALE), text, font=f, fill=fill)

centered("3EN", 118, font(68), (255, 245, 247, 255))
d.rounded_rectangle((70*SCALE, 198*SCALE, 186*SCALE, 201*SCALE),
                     radius=2*SCALE, fill=(245, 24, 48, 255))
centered("INSPECT", 207, font(15), (255, 255, 255, 255))
im = im.resize((SIZE, SIZE), Image.Resampling.LANCZOS)
im.save("3en.png", "PNG")
im.save("3en.ico", "ICO", sizes=[(256,256),(128,128),(64,64),(48,48),(32,32),(16,16)])
