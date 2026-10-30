from PIL import Image, ImageDraw, ImageFont

SIZE = 256
image = Image.new("RGBA", (SIZE, SIZE), (7, 10, 18, 255))
draw = ImageDraw.Draw(image)
draw.ellipse((12, 12, 244, 244), fill=(10, 16, 30, 255), outline=(35, 132, 255, 255), width=9)
draw.ellipse((27, 27, 229, 229), outline=(48, 75, 120, 255), width=2)
font = None
for candidate in (
    "C:/Windows/Fonts/arialbd.ttf",
    "C:/Windows/Fonts/seguisb.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
):
    try:
        font = ImageFont.truetype(candidate, 78)
        break
    except OSError:
        pass
if font is None:
    font = ImageFont.load_default()
text = "3EN"
box = draw.textbbox((0, 0), text, font=font, stroke_width=1)
x = (SIZE - (box[2] - box[0])) / 2 - box[0]
y = (SIZE - (box[3] - box[1])) / 2 - box[1] - 3
draw.text((x, y), text, font=font, fill=(235, 243, 255, 255),
          stroke_width=1, stroke_fill=(35, 132, 255, 255))
image.save("3en.ico", format="ICO", sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])
