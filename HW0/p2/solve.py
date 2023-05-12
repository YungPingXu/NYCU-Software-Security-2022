import base64

nine = base64.b64decode('wcvGwPze6PKg9eLY6/Lk7P7Y8+/m89jO2O/m8eLY5tjz7+7p4Njh6PXY9+bp5Obs4vT6')
for i in nine:
    print(chr(i ^ 135), end="")