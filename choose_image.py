"""Choose any local image and view a short ScamShield report."""

from __future__ import annotations

from tkinter import Tk, filedialog

from scamshield import run_scamshield_workflow


def choose_image() -> str:
    window = Tk()
    window.withdraw()
    window.attributes("-topmost", True)
    image_path = filedialog.askopenfilename(
        title="Choose a screenshot or image to check",
        filetypes=[("Images", "*.png *.jpg *.jpeg *.webp *.bmp"), ("All files", "*.*")],
    )
    window.destroy()
    return image_path


def print_report(result: dict) -> None:
    print("\nSCAMSHIELD REPORT")
    print("=" * 40)
    if result["status"] in {"failed", "invalid_input"}:
        print("Could not analyse this image.")
        print(result["errors"][0]["message"])
        return

    extracted = result["extracted_information"]
    cyber = result["cybersecurity_analysis"]
    print(f"Risk: {cyber['risk_level']} ({cyber['risk_score']}/100)")
    print(f"Likely type: {cyber['scam_type'].replace('_', ' ').title()}")
    print("\nText found:")
    print(extracted["text"] or "No readable text found.")
    if extracted["qr_data"]:
        print(f"\nQR data: {', '.join(extracted['qr_data'])}")
    if extracted["urls"]:
        print(f"URLs: {', '.join(extracted['urls'])}")

    indicators = [item["label"] for item in cyber["indicators"]]
    print("\nWarning signs:")
    print(", ".join(indicators) if indicators else "No specific warning signs found.")
    print("\nWhat to do:")
    for item in cyber["recommendations"][:3]:
        print(f"- {item}")
    if result["status"] == "partial":
        print("\nNote: The cybersecurity report is available, but the AI explanation was unavailable.")


def main() -> None:
    image_path = choose_image()
    if not image_path:
        print("No image selected.")
        return
    print_report(run_scamshield_workflow(image_path))


if __name__ == "__main__":
    main()
