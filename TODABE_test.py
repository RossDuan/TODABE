"""
:Authors: Pengfei Duan, Hongmin Gao, Zhaofeng Ma, Tian Tian, Jiyuan Song
:Date:            07/2024

Title: "Blockchain-enabled Secure Data Sharing with Traceability and Outsourced Decryption in IoT"

For Performance Test
"""
from charm.toolbox.pairinggroup import PairingGroup, GT, G1, pair
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad, unpad
from TODABE import TOD_ABE
import datetime
import time

def main():
    trial = 100
    Test_KeyGen = False
    Test_Encrypt = False
    Test_Decrypt_lo = False
    Test_Transform = False
    Test_Decrypt_od = False
    Test_WTrace = False

    group = PairingGroup('SS512')
    todabe = TOD_ABE(group, 50)

    Msg = group.random(GT) 
    print("The original message is:", Msg)

    if Test_KeyGen:
        print("KeyGen Bench")
        dict_case = {1: 'A', 2: 'B', 3: 'C', 4: 'D'}
        # Use 'with' statement for safe opening and closing of files
        with open('result_KeyGen.txt', 'w+') as f:
            f.write('KeyGen Bench\n')
            current_time = datetime.datetime.now()
            formatted_time = current_time.strftime('%Y-%m-%d %H:%M:%S')
            f.write('Current Time: ' + formatted_time + '\n')
            for case in range(1, 5):  # Simulating 4 experimental scenarios
                N_A = [10, 20, 20, 20]
                d = [50, 50, 100, 100]
                attributes = []
                start = 0
                end = 0
                total_time = 0  # Renamed 'T' to 'total_time' for clarity
                # Write case information upfront, no need to convert 'N_A' to string in each iteration
                f.write(f"Case {dict_case[case]}: N_A = {N_A[case-1]} ")
                attributes = [f"{attr}" for attr in range(1, N_A[case-1]+1)]#属性数量

                (pk, msk, fingerprint, ID) = todabe.Setup(d[case-1],10)
                # print(attributes,fingerprint)
                # Loop through the number of AuthSetups for the current case
                start = time.time()
                for _ in range(trial):
                    alice_keys = todabe.KeyGen(pk, msk, attributes, fingerprint)
                end = time.time()
                total_time = (end - start)
                average_time = total_time / trial
                f.write(f" {average_time}\n")

    if Test_Encrypt:
        print ("Encrypt Bench")                 
        dict_case = {1: 'A', 2: 'B', 3: 'C', 4: 'D'}
        ap_case = {1: '(1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10)', 2: '(1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10 and 11 and 12 and 13 and 14 and 15 and 16 and 17 and 18 and 19 and 20)', 3: '(1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10 and 11 and 12 and 13 and 14 and 15 and 16 and 17 and 18 and 19 and 20 and 21 and 22 and 23 and 24 and 25 and 26 and 27 and 28 and 29 and 30)', 4: '(1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10 and 11 and 12 and 13 and 14 and 15 and 16 and 17 and 18 and 19 and 20 and 21 and 22 and 23 and 24 and 25 and 26 and 27 and 28 and 29 and 30 and 31 and 32 and 33 and 34 and 35 and 36 and 37 and 38 and 39 and 40)'}
        with open('result_Encrypt.txt', 'w+') as f:
            f.write('Encrypt Bench\n')
            # 获取当前时间
            current_time = datetime.datetime.now()
            # 格式化时间
            formatted_time = current_time.strftime('%Y-%m-%d %H:%M:%S')
            f.write('Current Time: ' + formatted_time + '\n')
            for case in range(1, 5):  # Simulating 4 experimental scenarios
                start = 0
                end = 0
                total_time = 0  # Renamed 'T' to 'total_time' for clarity
                # Write case information upfront, no need to convert 'N_A' to string in each iteration
                f.write(f"Case {dict_case[case]}: access_policy = {ap_case[case]}")
                d = [50, 50, 100, 100]
                (pk, msk, fingerprint, ID) = todabe.Setup(d[case-1],10)
                start = time.time()
                for _ in range(trial):
                    CT_or = todabe.Encrypt(pk, Msg, ap_case[case], d = len(fingerprint), k = None)
                end = time.time()
                total_time = (end - start)
                average_time = total_time / trial
                f.write(f" {average_time}\n")

    if Test_Decrypt_lo:
        print ("Decrypt_lo Bench")
        dict_case = {1: 'A', 2: 'B', 3: 'C', 4: 'D'}
        ap_case = {1: '(1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10)', 2: '(1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10 and 11 and 12 and 13 and 14 and 15 and 16 and 17 and 18 and 19 and 20)', 3: '(1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10 and 11 and 12 and 13 and 14 and 15 and 16 and 17 and 18 and 19 and 20 and 21 and 22 and 23 and 24 and 25 and 26 and 27 and 28 and 29 and 30)', 4: '(1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10 and 11 and 12 and 13 and 14 and 15 and 16 and 17 and 18 and 19 and 20 and 21 and 22 and 23 and 24 and 25 and 26 and 27 and 28 and 29 and 30 and 31 and 32 and 33 and 34 and 35 and 36 and 37 and 38 and 39 and 40)'}
        with open('result_Decrypt_lo.txt', 'w+') as f:
            f.write('Decrypt_lo Bench\n')
            current_time = datetime.datetime.now()
            formatted_time = current_time.strftime('%Y-%m-%d %H:%M:%S')
            f.write('Current Time: ' + formatted_time + '\n')
            for case in range(1, 5):
                N_A = [10, 20, 30, 40]
                d = [50, 50, 100, 100]
                attributes = []
                start = 0
                end = 0
                total_time = 0
                (pk, msk, fingerprint, ID) = todabe.Setup(d[case-1],10)
                attributes = [f"{attr}" for attr in range(1, N_A[case-1]+1)]
                alice_keys = todabe.KeyGen(pk, msk, attributes, fingerprint)
                f.write(f"Case {dict_case[case]}: access_policy = {ap_case[case]}")
                CT_or = todabe.Encrypt(pk, Msg, ap_case[case], d = len(fingerprint), k = None)
                start = time.time()
                for _ in range(trial):
                    msg_lo = todabe.Decrypt_or(alice_keys, CT_or, 'original', fingerprint)
                end = time.time()
                total_time = (end - start)
                average_time = total_time / trial
                f.write(f" {average_time}\n")

    if Test_Transform:
        print ("Transform Bench")
        dict_case = {1: 'A', 2: 'B', 3: 'C', 4: 'D'}
        ap_case = {1: '(1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10)', 2: '(1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10 and 11 and 12 and 13 and 14 and 15 and 16 and 17 and 18 and 19 and 20)', 3: '(1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10 and 11 and 12 and 13 and 14 and 15 and 16 and 17 and 18 and 19 and 20 and 21 and 22 and 23 and 24 and 25 and 26 and 27 and 28 and 29 and 30)', 4: '(1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10 and 11 and 12 and 13 and 14 and 15 and 16 and 17 and 18 and 19 and 20 and 21 and 22 and 23 and 24 and 25 and 26 and 27 and 28 and 29 and 30 and 31 and 32 and 33 and 34 and 35 and 36 and 37 and 38 and 39 and 40)'}
        with open('result_Transform.txt', 'w+') as f:
            f.write('Transform Bench\n')
            current_time = datetime.datetime.now()
            formatted_time = current_time.strftime('%Y-%m-%d %H:%M:%S')
            f.write('Current Time: ' + formatted_time + '\n')
            for case in range(1, 5):
                N_A = [10, 20, 30, 40]
                d = [50, 50, 100, 100]
                attributes = []
                start = 0
                end = 0
                total_time = 0
                (pk, msk, fingerprint, ID) = todabe.Setup(d[case-1],10)
                attributes = [f"{attr}" for attr in range(1, N_A[case-1]+1)]
                alice_keys = todabe.KeyGen(pk, msk, attributes, fingerprint)
                f.write(f"Case {dict_case[case]}: access_policy = {ap_case[case]}")
                CT_or = todabe.Encrypt(pk, Msg, ap_case[case], d = len(fingerprint), k = None)
                TK, RK = todabe.TKGen(alice_keys)
                start = time.time()
                for _ in range(trial):
                    CT_prime = todabe.Transform(TK, CT_or)
                end = time.time()
                total_time = (end - start)
                average_time = total_time / trial
                f.write(f" {average_time}\n")

    if Test_Decrypt_od:
        print ("Decrypt_od Bench")
        dict_case = {1: 'A', 2: 'B', 3: 'C', 4: 'D'}
        ap_case = {1: '(1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10)', 2: '(1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10 and 11 and 12 and 13 and 14 and 15 and 16 and 17 and 18 and 19 and 20)', 3: '(1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10 and 11 and 12 and 13 and 14 and 15 and 16 and 17 and 18 and 19 and 20 and 21 and 22 and 23 and 24 and 25 and 26 and 27 and 28 and 29 and 30)', 4: '(1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10 and 11 and 12 and 13 and 14 and 15 and 16 and 17 and 18 and 19 and 20 and 21 and 22 and 23 and 24 and 25 and 26 and 27 and 28 and 29 and 30 and 31 and 32 and 33 and 34 and 35 and 36 and 37 and 38 and 39 and 40)'}
        with open('result_Decrypt_od.txt', 'w+') as f:
            f.write('Decrypt_od Bench\n')
            current_time = datetime.datetime.now()
            formatted_time = current_time.strftime('%Y-%m-%d %H:%M:%S')
            f.write('Current Time: ' + formatted_time + '\n')
            for case in range(1, 5):
                N_A = [10, 20, 30, 40]
                d = [50, 50, 100, 100]
                attributes = []
                start = 0
                end = 0
                total_time = 0
                (pk, msk, fingerprint, ID) = todabe.Setup(d[case-1],10)
                attributes = [f"{attr}" for attr in range(1, N_A[case-1]+1)]
                alice_keys = todabe.KeyGen(pk, msk, attributes, fingerprint)
                f.write(f"Case {dict_case[case]}: access_policy = {ap_case[case]}")
                CT_or = todabe.Encrypt(pk, Msg, ap_case[case], d = len(fingerprint), k = None)
                TK, RK = todabe.TKGen(alice_keys)
                CT_prime = todabe.Transform(TK, CT_or)
                start = time.time()
                for _ in range(trial):
                    msg_od = todabe.Decrypt_od(CT_prime, RK)
                end = time.time()
                total_time = (end - start)
                average_time = total_time / trial
                f.write(f"{average_time}\n")  

    if Test_WTrace:
        print ("WTrace Bench")
        dict_case = {1: 'A', 2: 'B', 3: 'C', 4: 'D'}
        ap_case = {1: '(1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10)', 2: '(1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10)', 3: '(1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10)', 4: '(1 and 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10 and 11 and 12 and 13 and 14 and 15 and 16 and 17 and 18 and 19 and 20)'}
        with open('result_WTrace.txt', 'w+') as f:
            f.write('WTrace Bench\n')
            current_time = datetime.datetime.now()
            formatted_time = current_time.strftime('%Y-%m-%d %H:%M:%S')
            f.write('Current Time: ' + formatted_time + '\n')
            for case in range(1, 5):
                N_A = [10, 20, 20, 20]
                d = [50, 50, 100, 100]
                attributes = []
                start = 0
                end = 0
                total_time = 0
                (pk, msk, fingerprint, ID) = todabe.Setup(d[case-1],10)
                attributes = [f"{attr}" for attr in range(1, N_A[case-1]+1)]
                alice_keys = todabe.KeyGen(pk, msk, attributes, fingerprint)
                f.write(f"Case {dict_case[case]}: access_policy = {ap_case[case]}")
                CT_or = todabe.Encrypt(pk, Msg, ap_case[case], d = len(fingerprint), k = None)
                TK, RK = todabe.TKGen(alice_keys)
                start = time.time()
                for _ in range(trial):
                    fingerprint_WT = todabe.WTrace(pk, alice_keys, len(fingerprint))
                end = time.time()
                total_time = (end - start)
                average_time = total_time / trial
                f.write(f" {average_time}\n")
                if fingerprint_WT == fingerprint:
                    print("White-box tracing is successful, the codeword is:", fingerprint_WT)
                else:
                    print("White-box tracing fails!")
        
                
if __name__ == "__main__":
    debug = True
    main()
