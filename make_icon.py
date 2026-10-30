from PIL import Image, ImageDraw, ImageFont, ImageFilter

SIZE = 256
SCALE = 3
canvas_size = SIZE * SCALE

# Dark base with a strong red glow for the 3EN Inspect Team identity.
image = Image.new("RGBA", (canvas_size, canvas_size), (5, 5, 8, 255))
glow = Image.new("RGBA", image.size, (0, 0, 0, 0))
glow_draw = ImageDraw.Draw(glow)
glow_draw.ellipse((22*SCALE, 18*SCALE, 234*SCALE, 238*SCALE),
                  fill=(220, 0, 28, 115))
glow = glow.filter(ImageFilter.GaussianBlur(27*SCALE))
image = Image.alpha_composite(image, glow)
draw = ImageDraw.Draw(image)

# Bold red badge and inner outline.
draw.rounded_rectangle((9*SCALE, 9*SCALE, 247*SCALE, 247*SCALE),
                       radius=42*SCALE, fill=(12, 8, 12, 255),
                       outline=(235, 18, 42, 255), width=7*SCALE)
draw.rounded_rectangle((21*SCALE, 21*SCALE, 235*SCALE, 235*SCALE),
                       radius=34*SCALE, outline=(105, 8, 25, 255),
                       width=2*SCALE)

def load_font(size):
    for candidate in (
        "C:/Windows/Fonts/arialbd.ttf",
        "C:/Windows/Fonts/seguisb.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    ):
        try:
            return ImageFont.truetype(candidate, size*SCALE)
        except OSError:
            pass
    return ImageFont.load_default()

def centered_text(text, y, font, fill, stroke_width=0, stroke_fill=(0, 0, 0, 255)):
    bbox = draw.textbbox((0, 0), text, font=font, stroke_width=stroke_width*SCALE)
    text_width = bbox[2] - bbox[0]
    x = (canvas_size - text_width) / 2 - bbox[0]
    draw.text((x, y*SCALE), text, font=font, fill=fill,
              stroke_width=stroke_width*SCALE, stroke_fill=stroke_fill)

# Main brand mark.
centered_text("3EN", 65, load_font(76), (255, 245, 247, 255),
              stroke_width=2, stroke_fill=(220, 12, 38, 255))

# Red divider and the requested team name beneath the main mark.
draw.rounded_rectangle((70*SCALE, 157*SCALE, 186*SCALE, 160*SCALE),
                       radius=2*SCALE, fill=(245, 24, 48, 255))
centered_text("Inspect Team", 171, load_font(19), (255, 255, 255, 255))

image = image.resize((SIZE, SIZE), Image.Resampling.LANCZOS)
image.save("3en.png", format="PNG")
image.save("3en.ico", format="ICO",
           sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])
