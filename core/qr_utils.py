from PIL import Image
import qrcode

def transparent_qr_image(data: str, *, box_size: int=10, border: int=4) -> Image.Image:
    qr = qrcode.QRCode(box_size=box_size, border=border)
    qr.add_data(data)
    qr.make(fit=True)
    image = qr.make_image(fill_color='black', back_color='white').convert('RGBA')
    pixels = []
    for red, green, blue, alpha in image.getdata():
        if alpha == 0 or (red >= 245 and green >= 245 and (blue >= 245)):
            pixels.append((255, 255, 255, 0))
        else:
            pixels.append((0, 0, 0, 255))
    image.putdata(pixels)
    return image