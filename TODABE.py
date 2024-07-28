'''
:Authors: Pengfei Duan, Zhaofeng Ma, Tian Tian, Jiyuan Song
:Date:            07/2024

Title: "Blockchain-enabled Secure Data Sharing with Traceability and Outsourced Decryption in IoT"

'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.msp import MSP
import random
import hashlib

debug = False


class TOD_ABE(ABEnc):

    def __init__(self, group_obj, uni_size, verbose=False):
        ABEnc.__init__(self)
        self.group = group_obj
        self.uni_size = uni_size  # bound on the size of the universe of attributes
        self.util = MSP(self.group, verbose)

    def Setup(self, lambda1, NN):
        """
        Generates public key and master secret key.
        """
        codewords = [bin(random.getrandbits(lambda1))[2:].zfill(lambda1) for _ in range(NN)]
        tracking_key = hashlib.sha256(("".join(codewords)).encode()).hexdigest()

        if debug:
            print('Setup algorithm:\n')

        # pick a random element each from two source groups and pair them
        alpha, beta, delta = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)
        g = self.group.random(G1)
        h = ['']
        h = [self.group.random(G1) for _ in range(self.uni_size)]
        g_alpha = g ** alpha
        g_beta = g ** beta
        g_delta = g ** delta
        e_gg_alpha = pair(g_alpha, g)

        pp = {'g': g, 'g_beta': g_beta, 'g_delta': g_delta, 'e_gg_alpha': e_gg_alpha, 'h': h}
        msk = {'g_alpha': g_alpha, 'rk': tracking_key}
        ID = random.randint(1, NN)
        codeword = codewords[ID-1]
        #Each user is identified by a unique tuple, which consists of a codeword f and an ID.
        return pp, msk, codeword, ID

    def KeyGen(self, pk, msk, attr_list, codeword):
        """
        Generate a key for a set of attributes.
        """
        if debug:
            print('Key generation algorithm:\n')

        r = self.group.random(ZR)
        K1 = msk['g_alpha'] * (pk['g_beta'] ** r)
        K2 = pk['g'] ** r

        K3 = {}
        K4 = {}
        for attr in attr_list:
            K3[attr] = pk['h'][int(attr)] ** r
            temp_k = {}
            for k in range(1, len(codeword)+1):
                temp_k[k] = (pk['h'][int(attr)] * pk['g_delta'] ** (k + int(codeword[k-1]))) ** r
            K4[attr] = temp_k
        return {'attr_list': attr_list, 'K1': K1, 'K2': K2, 'K3': K3, 'K4': K4}

    def Encrypt(self, pk, msg, policy_str, d=None, k=None):
        """
         Encrypt a message M under a monotone span program.
        """

        if debug:
            print('Encryption algorithm:\n')

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # pick randomness
        u = []
        for i in range(num_cols):
            rand = self.group.random(ZR)
            u.append(rand)
        s = u[0]    # shared secret
        C_0 =  msg * (pk['e_gg_alpha'] ** s)
        C_1 = pk['g'] ** s
        if k is None and d is not None:
            k = random.choice(range(1, d+1))
        if k is None: 
            raise ValueError("----Codeword length 'd' or specified position 'k' must be provided----")
        
        C_2_0 = {}
        C_2_1 = {}
        C_3 = {}
        C_4 = {}
        for attr, row in mono_span_prog.items():
            cols = len(row)
            sum = 0
            for i in range(cols):
                sum += row[i] * u[i]
            attr_stripped = self.util.strip_index(attr)
            t_attr = self.group.random(ZR)
            c_attr_0 = (pk['g_beta'] ** sum) / ((pk['h'][int(attr_stripped)] * pk['g_delta'] ** k) ** t_attr)
            c_attr_1 = (pk['g_beta'] ** sum) / ((pk['h'][int(attr_stripped)] * pk['g_delta'] ** (k+1)) ** t_attr)
            c_3_attr = (pk['g_beta'] ** sum) / (pk['h'][int(attr_stripped)] ** t_attr)
            c_4_attr = pk['g'] ** t_attr
            C_2_0[attr] = c_attr_0
            C_2_1[attr] = c_attr_1
            C_3[attr] = c_3_attr
            C_4[attr] = c_4_attr

        return {'policy': policy, 'k': k, 'C_0': C_0, 'C_1': C_1, 'C_2_0': C_2_0, 'C_2_1': C_2_1, 'C_3': C_3, 'C_4': C_4}

    def Decrypt_lo(self, SK, CT, mode, f=None):
        """
        Decrypt original ciphertext with key.
        """
        if debug:
            print('Decryption algorithm:\n')

        nodes = self.util.prune(CT['policy'], SK['attr_list'])
        if not nodes:
            print ("Policy not satisfied.")
            return None

        e_K1_C1 = pair(SK['K1'], CT['C_1'])
        
        prodG = 1
        prodGT = 1
        
        # Decide which C_x to use based on the mode
        if mode == 'original':
            Cx = CT['C_2_1'] if int(f[CT['k']-1]) else CT['C_2_0']
        elif mode == 'BT_prime':
            Cx = CT['C_2_1']
        elif mode == 'BT_prime_prime':
            Cx = CT['C_2_0']
        else:
            raise ValueError("Invalid mode")

        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)
            prodG *= Cx[attr]
            prodGT *= pair(SK['K4'][attr_stripped][CT['k']], CT['C_4'][attr])
        return (CT['C_0'] * pair(prodG, SK['K2']) * prodGT) / e_K1_C1
    
    def TKGen(self, SK):
        z = self.group.random(ZR)
        TK_1 = SK['K1'] ** (1/z)
        TK_2 = SK['K2'] ** (1/z)
        
        TK_3 = {}
        for attr in SK['attr_list']:
            TK_3[attr] = SK['K3'][attr] ** (1/z)
        
        return {'attr_list': SK['attr_list'], 'TK_1': TK_1, 'TK_2': TK_2, 'TK_3': TK_3}, z

    def Transform(self, TK, CT):
        if debug:
            print('Transformation algorithm:\n')

        nodes = self.util.prune(CT['policy'], TK['attr_list'])
        if not nodes:
            print ("Policy not satisfied.")
            return None
        part1 = pair(CT['C_1'], TK['TK_1'])
        part2_1 = 1
        part3 = 1

        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)
            part2_1 *= CT['C_3'][attr]
            part3 *= pair(TK['TK_3'][attr_stripped], CT['C_4'][attr])
            
        CT_prime = part1 / (pair(part2_1, TK['TK_2']) * part3)
        
        return {'CT_prime_1': CT_prime, 'CT_prime_0': CT['C_0']}

    def Decrypt_od(self, CT_prime, RK):
        """
         Decrypt ciphertext ctxt with key key.
        """

        if debug:
            print('Decryption algorithm:\n')
        
        return CT_prime['CT_prime_0'] / (CT_prime['CT_prime_1'] ** RK)

    def WTrace(self, pp, sk, d):
        w_codeword = ''
        if pair(sk['K1'], pp['g']) == pp['e_gg_alpha'] * pair(sk['K2'], pp['g_beta']):
            print('White-box tracing starts!')
            attr_test = '1'
            for k in range(1,d+1):
                if pair(sk['K4'][attr_test][k], pp['g']) == pair(sk['K2'], pp['g_delta'] ** k * pp['h'][int(attr_test)]):
                    w_codeword += '0'
                else:
                    if pair(sk['K4'][attr_test][k], pp['g']) == pair(sk['K2'], pp['g_delta'] ** (k+1) * pp['h'][int(attr_test)]):
                        w_codeword += '1'
                    else:
                        print('White-box tracing fails!')           
        else:
            print('White-box tracing fails!')
        
        return w_codeword
    
    def BTrace(self, pk, sk, access_policy_prime, len):
        print("Black-box tracing starts!")
        b_codeword = ''
        for k_prime in range(1, len+1):#对[d]中的每一位都进行检查
            CT_ori = ''
            message_prime = self.group.random(GT)
            CT_ori1 = self.Encrypt(pk, message_prime, access_policy_prime, d = None, k = k_prime)
            CT_ori2 = self.Encrypt(pk, message_prime, access_policy_prime, d = None, k = k_prime)
            keys_prime = CT_ori1['C_2_0'].keys()
            for key in keys_prime:
                CT_ori1['C_2_0'][key] = (self.group.random(G1))
            message_prime_Dec = self.Decrypt_lo(sk, CT_ori1, 'BT_prime')
            if message_prime_Dec == message_prime:
                b_codeword += '1'
            else:
                keys_prime_prime = CT_ori2['C_2_1'].keys()
                for key_pp in keys_prime_prime:
                    CT_ori2['C_2_1'][key_pp] = (self.group.random(G1))
                message_prime_prime_Dec = self.Decrypt_lo(sk, CT_ori2, 'BT_prime_prime')
                if message_prime_prime_Dec == message_prime:
                    b_codeword += '0'
        return b_codeword


if __name__ == '__main__':
    group = PairingGroup('SS512')
    abeod = TOD_ABE(group, 10) #10 represents the size of the attribute universe
    
    Msg = group.random(GT)
    print("The original message is:", Msg)

    #System Initialization
    (pk, msk, codeword, ID) = abeod.Setup(10, 10)

    #Secret Key Generation
    gid_alice = "alice"
    alice_attributes = ['1', '4', '5']
    gid_bob = "bob"
    bob_attributes = ['2', '4', '9']
    alice_keys = abeod.KeyGen(pk, msk, alice_attributes, codeword)
    bob_keys = abeod.KeyGen(pk, msk, bob_attributes, codeword)

    #Data Processing
    access_policy = '(1 or 2) and (4) and (5 or 9)'
    CT = abeod.Encrypt(pk, Msg, access_policy, d = len(codeword), k = None)

    #Ciphertext Decryption without Outsourcing Decryption
    decrypted_or_msg = abeod.Decrypt_lo(alice_keys, CT, 'original', codeword)
    print("decr_or GT_msg:", decrypted_or_msg)

    if Msg == decrypted_or_msg:
        print("Original ciphertext is decrypted successfully!")
    
    #Outsourcing decryption
    TK, RK = abeod.TKGen(bob_keys)
    CT_prime = abeod.Transform(TK, CT)
    
    #Ciphertext Decryption with Outsourcing Decryption
    decrypted_od_msg = abeod.Decrypt_od(CT_prime, RK)
    print("decr_od GT_msg:", decrypted_od_msg)
    
    if Msg == decrypted_od_msg:
        print("The partially decrypted ciphertext is decrypted successfully!")

    #White-box Trace
    codeword_WT = abeod.WTrace(pk, alice_keys, len(codeword))
    
    if codeword_WT == codeword:
        print("White-box tracing is successful, the codeword is:", codeword_WT)
    else:
        print("White-box tracing fails!")
    
    #Black-box Trace
    codeword_prime = '1101101101' #This is the collusion fingerprint used to construct the decryption device.
    
    test_attrs = ['1', '2', '4']
    
    sk_prime = abeod.KeyGen(pk, msk, test_attrs, codeword_prime)
    
    access_policy_prime = '((1 and 2) and (3 or 4))' #This is the access policy that the decryption device satisfies
    
    codeword_BT = abeod.BTrace(pk, sk_prime, access_policy_prime, len(codeword_prime))
    
    if codeword_BT == codeword_prime:
        print("Black-box tracing is successful, the codeword is:", codeword_BT)
    else:
        print("Black-box tracing fails！")