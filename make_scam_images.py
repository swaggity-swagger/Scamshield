from PIL import Image, ImageDraw, ImageFont

# Open our QR code
qr = Image.open("test_images/test_qr.png")

# Resize QR
qr = qr.resize((250, 250))

# Create a white image
image = Image.new("RGB", (800, 700), "white")

draw = ImageDraw.Draw(image)

# Write our fake scam message
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

# Put QR code on the image
image.paste(qr, (275, 330))

# Save
image.save("test_images/scam_combined.png")

print("Combined scam image created!")