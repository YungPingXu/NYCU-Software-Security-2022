# dropper/script.py 
v62 = [0] * 13
v62[0] = -66
v62[1] = -102
v62[2] = -117
v62[3] = -99
v62[4] = -117
v62[5] = -109
v62[6] = -54
v62[7] = -54
v62[8] = -39
v62[9] = -110
v62[10] = -103
v62[11] = -104
v62[12] = -13
v62 =  [i ^ ~(v62[i]) for i in range(len(v62))]
print(bytes(v62).decode())

v64 = [0] * 13
v64[0] = -76
v64[1] = -101
v64[2] = -113
v64[3] = -110
v64[4] = -98
v64[5] = -106
v64[6] = -54
v64[7] = -54
v64[8] = -39
v64[9] = -110
v64[10] = -103
v64[11] = -104
v64[12] = -13
v64 = [i ^ ~(v64[i]) for i in range(len(v64))]
print(bytes(v64).decode())

v74 = [_ for _ in range(21)]
v74[0] = -68
v74[1] = -116
v74[2] = -124
v74[3] = -116
v74[4] = -113
v74[5] = -69
v74[6] = -102
v74[7] = -119
v74[8] = -126
v74[9] = -97
v74[10] = -121
v74[11] = -111
v74[12] = -80
v74[13] = -99
v74[14] = -97
v74[15] = -124
v74[16] = -118
v74[17] = -106
v74[18] = -103
v74[19] = -69
v74[20] = -21
v74 = [i ^ ~(v74[i]) for i in range(len(v74))]
print(bytes(v74).decode())