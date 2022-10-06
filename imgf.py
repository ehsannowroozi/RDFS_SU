import pandas as pd
from sklearn.preprocessing import OrdinalEncoder
from PIL import Image
import matplotlib.pyplot as plt
from ipaddress import IPv4Address

import numpy as np
import csv


'''
with open("C:/Users/M2/Desktop/UNSW/UNSW-NB15_1.csv", "r", encoding='utf-8-sig') as file_1:
    file_1 = file_1.read()
wf = open("merge.csv", "a")
wf.write(file_1)
wf.close()

with open("C:/Users/M2/Desktop/UNSW/UNSW-NB15_2.csv", "r", encoding='utf-8-sig') as file_2:
    file_2 = file_2.read()
wf = open("merge.csv", "a")
wf.write(file_2)
wf.close()

with open("C:/Users/M2/Desktop/UNSW/UNSW-NB15_3.csv", "r", encoding='utf-8-sig') as file_3:
    file_3 = file_3.read()
wf = open("merge.csv", "a")
wf.write(file_3)
wf.close()

with open("C:/Users/M2/Desktop/UNSW/UNSW-NB15_4.csv", "r", encoding='utf-8-sig') as file_4:
    file_4 = file_4.read()
wf = open("merge.csv", "a")
wf.write(file_4)
wf.close()

with open("C:/Users/M2/Desktop/FX/merge.csv", "r", encoding='utf-8-sig') as file:
    file = file.read()
table = file.splitlines( )

for index, row in enumerate(table):
    table[index] = row.split(",")
    table[index][0] = int(IPv4Address(table[index][0]))
    table[index][2] = int(IPv4Address(table[index][2]))
    
    try:
        table[index][1] = int(table[index][1])
    except:
        try:
            table[index][1] = int(table[index][1], 16)
        except: 
            table[index][1] = 0

    try:
        table[index][3] = int(table[index][3])
    except:
        try:
            table[index][3] = int(table[index][3], 16)
        except:
            table[index][3] = 0

    for i in range(6,47):
        if i != 13:
            if table[index][i] != '' and table[index][i] != ' ':
                table[index][i] = float(table[index][i])
            else:
                table[index][i] = float(0)


    del table[index][48]
    print (index)
            

with open('result.csv','w') as f:
    writer = csv.writer(f)
    writer.writerows(table)
'''



headers = ["srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes", "sttl", "dttl", \
    "sloss", "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts", "swin", "dwin", "stcpb", "dtcpb", \
         "smeansz", "dmeansz", "trans_depth", "res_bdy_len", "Sjit", "Djit", "Stime", "Ltime", \
             "Sintpkt", "Dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl", \
                  "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", \
                      "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat"]

#df = pd.DataFrame(table, columns =headers)
df = pd.read_csv("C:/Users/M2/Desktop/FX/merged.csv", header=None, names=headers, na_values="?" )
df.head()

df = df.fillna({"attack_cat": "normal"})
ord_enc = OrdinalEncoder()
df["proto"] = ord_enc.fit_transform(df[["proto"]])
df["state"] = ord_enc.fit_transform(df[["state"]])
df["service"] = ord_enc.fit_transform(df[["service"]])
df['attack_cat'] = df['attack_cat'].str.strip()
'''
df["attack_cat_code"] = ord_enc.fit_transform(df[["attack_cat"]])
df=df.reindex(columns=["srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes", "sttl", "dttl", \
    "sloss", "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts", "swin", "dwin", "stcpb", "dtcpb", \
         "smeansz", "dmeansz", "trans_depth", "res_bdy_len", "Sjit", "Djit", "Stime", "Ltime", \
             "Sintpkt", "Dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl", \
                  "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", \
                      "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat_code", \
                           "attack_cat"])
'''

dos = df.loc[df['attack_cat'] == 'DoS']
normal = df.loc[df['attack_cat'] == 'normal']
exploits = df.loc[df['attack_cat'] == 'Exploits']
fuzzer = df.loc[df['attack_cat'] == 'Fuzzers']
backdoor = df.loc[df['attack_cat'] == 'Backdoor']
reconnaissance = df.loc[df['attack_cat'] == 'Reconnaissance']
analysis = df.loc[df['attack_cat'] == 'Analysis']
generic = df.loc[df['attack_cat'] == 'Generic']

for j in range(0,47):
        pd.to_numeric(exploits.iloc[:, j], downcast='float')
 
nd = exploits.iloc[:, :47].to_numpy()
# sort_nd = nd[nd[:, 46].argsort()]
sord_nd_features = nd[:,5:]
sord_nd_features_normed = 255*(sord_nd_features - sord_nd_features.min(0)) / sord_nd_features.ptp(0)

for i in range (0, 50000):
    array = np.reshape(sord_nd_features_normed[i], (7, 6))
    im = Image.fromarray(array)
    im= im.convert("L")
    im = im.resize((64, 64))
    im.save("C:/Users/M2/Desktop/FX/exploits/img_%d.jpg"%i)








