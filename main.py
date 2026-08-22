import cv2
import pytesseract

pytesseract.pytesseract.tesseract_cmd = (
    r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)

# Load image
image = cv2.imread("scam_combined.png")

# OCR
gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

gray = cv2.resize(
    gray,
    None,
    fx=2,
    fy=2
)

_, threshold = cv2.threshold(
    gray,
    150,
    255,
    cv2.THRESH_BINARY
)

text = pytesseract.image_to_string(threshold)

# QR detection
detector = cv2.QRCodeDetector()

data, points, _ = detector.detectAndDecode(image)

# Results
print("\n================================")
print("       SCAMSHIELD ANALYSIS")
print("================================")

print("\n----- EXTRACTED TEXT -----")
print(text)

print("\n----- QR ANALYSIS -----")

if data:
    print("QR Code Detected: YES")
    print("QR Data:", data)
else:
    print("QR Code Detected: NO")
