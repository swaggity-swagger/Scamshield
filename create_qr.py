import qrcode

url = "https://example.com"

qr = qrcode.make(url)

qr.save("test_images/test_qr.png")

print("QR code created!")