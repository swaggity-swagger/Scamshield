from PIL import Image, ImageDraw

qr = Image.open("test_qr.png")

qr = qr.resize((250, 250))

image = Image.new("RGB", (800, 700), "white")

draw = ImageDraw.Draw(image)

draw.text(
    (50, 50),
    "URGENT!",
    fill="black"
)

draw.text(
    (50, 120),
    "Your bank account will be blocked today.",
    fill="black"
)

draw.text(
    (50, 180),
    "Complete your KYC immediately.",
    fill="black"
)

draw.text(
    (50, 240),
    "Scan the QR code to verify your account.",
    fill="black"
)

image.paste(qr, (275, 330))

image.save("scam_combined.png")

print("Combined scam image created!")
