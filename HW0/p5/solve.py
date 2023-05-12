import base64

nine_revenge = base64.b64decode('wcvGwpuiPzT7+LY9PPo6eLpuiY7vTY6ejz2OH1pui5uDu6+LY5unpui+6uj14qmpuipqfo='.replace("pui", ""))
for i in nine_revenge:
    print(chr(i ^ 135), end="")