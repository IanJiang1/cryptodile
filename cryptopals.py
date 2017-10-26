import string
from binascii import a2b_hex
from AES import *
import random

def hex2b64(hex_string):
    return hex_string.decode("hex").encode("base64");

def avg(num_list):
    return sum([float(a) for a in num_list])/len(num_list)

def StringXor(string1, string2):
    """Computes the bitwise xor of the unicode points of each strings"""    
    return "".join([chr(int(a.encode("hex"), 16)^int(string2[i].encode("hex"), 16)) for i,a in enumerate(string1)])

def StringXor_pad(string1, string2):
    """Computes the bitwise xor of the unicode points of each strings, padding with spaces if necessary"""
    length1 = len(string1)
    length2 = len(string2)
    def_length = max([length1, length2])
    string1 += (def_length - length1)*" "
    string2 += (def_length - length2)*" "
    return "".join([chr(int(a.encode("hex"), 16)^int(string2[i].encode("hex"), 16)) for i,a in enumerate(string1)])

def InStreamEncrypt(filename, xor_key, new_info):
    """Decrypts a file using the xor_key as the argument, appends new_info and then re-encrypts under the same key."""
    file = open(filename, "rb+");
    test_string = "".join(file.readlines())
    test_string = StringXor(test_string, "".join([xor_key[i % len(xor_key)] for i in range(len(test_string))]))
    test_string = test_string + "\n" + new_info[0] + "\n"+ "Username: " + new_info[1] + "\n" + "Passwd: " + new_info[2]
    crypt_string = StringXor(test_string, "".join([xor_key[i % len(xor_key)] for i in range(len(test_string))]))
    file.truncate(0)
    file.seek(0)
    file.write(crypt_string)
    file.close

def Load_LangMetric(charfreq_filename, split_char, lettres):
    """Loads a frequency table of characters from a given filename"""    
    char_freq = [0.01*float(a) for a in open(charfreq_filename, "r+").read().split(split_char) if a != ""]
    lang_freq = dict()
    for i,lettre in enumerate(lettres):
        lang_freq[lettre] = char_freq[i]
    return lang_freq

def LangMetric(test_string, lang_freq):	
    """Computes a metric to determine how 'compatible' a string is with a given language based upon character frequencies in that language"""
    lang_metric = 0
    for a in test_string.lower():
        if a in lang_freq:
            lang_metric += lang_freq[a]
    return lang_metric

def LangMetric2(test_string, lang_freq):	
    """Computes a metric to determine how 'compatible' a string is with a given language based upon character frequencies in that language, using list comprehensions"""
    return sum([lang_freq[a] for a in test_string if a in lang_freq])

def Best_SingleXor(test_string, lang_freq):
    cur_best_score = 0
    best_string = ""
    best_lettre = ""
    for lettre in string.printable:
        new_string = StringXor(test_string,lettre*len(test_string))
        new_score = LangMetric(new_string, lang_freq)
        if  new_score > cur_best_score:
            cur_best_score = new_score
            best_string = new_string
            best_lettre = lettre
    return [best_string, best_lettre, cur_best_score]

def MaxScore(filename, lang_freq):
    """Computes the minimum score of each line from the given filename"""	    
    cur_best_score = 0
    best_string = ""    
    for line in [a2b_hex(a) for a in open(filename, "r+").read().split("\n")]:
        new_string = Best_SingleXor(line, lang_freq)        
        if new_string[1] > cur_best_score:
            best_string = new_string[0]
            cur_best_score = new_string[1]
    return [best_string, cur_best_score]

def sol4(filename):
    """Returns the string that is encoded by single-char encryption from a list of strings"""    
    lang_freq = Load_LangMetric("char_freq_english.txt", "\n", string.ascii_lowercase + " ")
    return MaxScore(filename, lang_freq)

def RepeatKeyEncrypt(test_string, key):
    """Encrypts a string based upon repeating key encryption"""
    return StringXor_pad(test_string, key*int(float(len(test_string))/len(key)))

def heebiejeebie(file, key):
    return RepeatKeyEncrypt(open(file, "r+").read().decode("hex"), key)

def EditDistance(bits1, bits2):
    return sum([1 for i,a in enumerate(bits1) if bits2[i] != a])
							
def EditDistances(test_string, max_keysize):
    test_string = "".join(format(ord(x),"b").zfill(8) for x in test_string)    
    return [float(EditDistance(test_string[:8*keysize],test_string[8*keysize:16*keysize]))/keysize for keysize in range(2,max_keysize)]
	
def EditDistances2(test_string, max_keysize):
    test_string = "".join(format(ord(x),"b").zfill(8) for x in test_string)
    return [0.5*(float(EditDistance(test_string[:8*keysize],test_string[8*keysize:16*keysize]))/keysize) + 0.5*(float(EditDistance(test_string[16*keysize:24*keysize],test_string[24*keysize:32*keysize]))/keysize) for keysize in range(2,max_keysize)]

def EditDistances3(test_string, max_keysize):
    test_string = "".join(format(ord(x),"b").zfill(8) for x in test_string)    
    return [float(EditDistance(test_string[8*keysize:16*keysize],test_string[24*keysize:32*keysize]))/keysize for keysize in range(2,max_keysize)]

def EditDistances4(test_string, max_keysize):
    test_string = "".join(format(ord(x),"b").zfill(8) for x in test_string)
    return [0.333333*(EditDistance(test_string[:8*keysize],test_string[8*keysize:16*keysize]) + EditDistance(test_string[8*keysize:16*keysize],test_string[16*keysize:24*keysize]) + EditDistances(test_string[16*keysize:24*keysize], test_string[24*keysize:32*keysize]))/keysize for keysize in range(2,max_keysize)]

def KeysizeGuesses(test_string, max_keysize):
    """returns the first few keysizes that yield the smallest string Hamming distances"""
    break_var = 1
    err_msg = "\n Please enter a keysize greater than 3 \n"
    while break_var == 1:
        distances1 = EditDistances(test_string, max_keysize)
        distances2 = EditDistances2(test_string, max_keysize)
        distances3 = EditDistances3(test_string, max_keysize)
        distances = [0.33333*(x + distances2[i] + distances3[i]) for i,x in enumerate(distances1)]
        distances_sorted = sorted(distances)
        if max_keysize > 11:
            return [distances.index(x) + 2 for x in distances_sorted[0:10]]
            breaK_var = 2
        elif max_keysize > 6:
            return [distances.index(x) + 2 for x in distances_sorted[0:5]]
            breaK_var = 2 
        elif max_keysize > 4:
            return [distances.index(x) + 2 for x in distances_sorted[0:3]]	
            break_var = 2
        else:
            print(err_msg)
            breaK_var = 1        

def Chunk_Keysize(test_string, keysize):
    div = int(float(len(test_string))/keysize)
    return [test_string[i*keysize:(i + 1)*keysize] for i in range(div)] + [test_string[div*keysize::]]	

def Chunk_transpose(test_string, keysize):
    chunks = Chunk_Keysize(test_string, keysize)
    return ["".join(x[i] for x in chunks if i < len(x)) for i in range(keysize)]
	
def Chunk_retranspose(chunks):
    """Takes chunks and fits it back to the original message"""
    return "".join("".join(x[i] for x in chunks) for i in range(min([len(x) for x in chunks])))

def Best_RepeatXor(test_string, keysize, lang_freq):
    """Takes a string and breaks into chunks of every ith character, up to keysize"""
    chunks = Chunk_transpose(test_string, keysize)
    return Chunk_retranspose([Best_SingleXor(x, lang_freq)[0] for x in chunks])

def sol7(filename, AES_size, init_key):
    """Decrypts file, assuming that it is encrypted in AES-128 ECB mode"""
    test_string = "".join(open(filename, "r").readlines()).decode("base64")
    inv = "".join(InvCipher(128, test_string[i*16:(i + 1)*16], init_key) for i in range(int(len(test_string)/16)))
    return inv
    

#def sol7(filename, lang_freq, max_keysize):
   # test_string = open(filename, "r+").read().decode("base64")
   # min_texts = [[keysize, Best_RepeatXor(test_string, keysize, lang_freq)] for keysize in KeysizeGuesses(test_string, max_keysize)]
   # scores = [LangMetric(x[1], lang_freq) for x in min_texts]
   # return [x[1] for x in min_texts][scores.index(max(scores))]

def sol8(filename):
    """Detects AES in ECB mode by computing the Hamming distances between consecutive groups of 16-bit strings"""
    test_string = open(filename, "r+").readlines()

    # removing last character in test_string
    test_string = [test_string[i][0:(len(test_string[i]) -1)] for i in range(len(test_string))]

    # Decoding each string assuming hex encoding. 
    test_string = [test_string[i].decode("hex") for i in range(len(test_string)) if len(test_string[i]) % 2 == 0]

    # Breaking each component up into 16-byte chunks (assuming AES-128 ECB)   
    test_string = [[test_string[i][j*16:(j + 1)*16] for j in range(int(len(test_string[i])/16))] for i in range(len(test_string))]
    

    hamming_distances = [[]]*len(test_string)    

    # Computing Hamming distances between unique pairs of blocks for each component of the test_string
    for i in range(len(test_string)):
        for j in range(len(test_string[i]) - 1):
            for k in range(j + 1,len(test_string[i])):
                hamming_distances[i] = hamming_distances[i] + [EditDistance("".join(format(ord(x), "b").zfill(8) for x in test_string[i][j]), "".join(format(ord(x), "b").zfill(8) for x in test_string[i][k]))]
    
    return hamming_distances

def pkcs7(test_string, block_size):
    """Pads test_string to multiple of block size using PKCS#7"""
    chrValue = (block_size - (len(test_string) % block_size)) % block_size
    return test_string + chr(chrValue)*chrValue

def sol10(filename, init_key):
    """Decrypts file, assuming that it is encrypted in AES-128 CBC mode, with an IV of \x00*16"""
    test_string = "".join(open(filename, "r").readlines()).decode("base64")
    inv = "".join(InvCipher(128, test_string[i*16:(i + 1)*16], init_key) for i in range(int(len(test_string)/16)))    
    ciph_shift = "\x00"*16 + test_string[0:(len(ciph) - 16)]
    return StringXor(inv, ciph_shift)

def rand_key(length):
    """generates a random string of bytes of the given length"""
    return "".join(chr(random.randint(0, 255)) for i in range(length))

def rand_AES(test_string):
    """Encrypts test_string (16 bytes) under AES-128 with a random key """
    init_key = rand_key(16)
    return cipher(128, test_string, init_key)

def AES_oracle(test_string):
    """Block encrypts a given input string using CBC or ECB randomly"""
    
    #Generates an initial key randomly.
    init_key = rand_key(16)

    #Appends a number of bytes to the beginning and end of test_string to make it a multiple of 16. 
    rand_block = "".join(chr(random.randint(0, 255)) for i in range(10))
    rand_block2 = "".join(chr(random.randint(0, 255)) for i in range(16 - (len(test_string + rand_block) % 16)))

    test_string = rand_block + test_string + rand_block2
    
    #Decides how to encode:
    decision = random.randint(0, 1)
    print(decision)

    #Encodes:
    if decision == 0:
        ciph_text = AES_ECB(test_string, init_key)
    elif decision == 1:
        #generates a random iv:
        test_iv = rand_key(16)

        ciph_text = AES_CBC(test_string, init_key, test_iv)

    return "".join(ciph_text)

def AES_ECB(input_string, init_key) :
    """encrypts a given input_string using AES-128 ECB encryption mode under key given in init_key, using PKCS 7 padding"""
    
    test_string = pkcs7(input_string, 16)    

    #Encrypts test_string one block at a time. 
    ciph_text = "".join(cipher(128, test_string[i*16:(i + 1)*16], init_key) for i in range(int(len(test_string)/16)))
    return ciph_text

def AES_CBC(input_string, init_key, test_iv):
    """encrypts a given input_string using AES-128 CBC encryption mode under key given in init_key, using PKCS 7 padding"""
    
    test_string = pkcs7(input_string, 16)    

    #Breaks test_string into chunks of cipher block length. 
    test_blocks = [test_string[i*16:(i + 1)*16] for i in range(int(len(test_string)/16))]
    
    ciph_text = []
    
    #Encodes test_string one block at a time. 
    for i in range(len(test_blocks)):
        if i != 0:
            ciph_text.append(cipher(128, StringXor(test_blocks[i], ciph_text[i-1]), init_key))
        elif i == 0:
            ciph_text.append(cipher(128, StringXor(test_blocks[i], test_iv), init_key))

    return ciph_text
    

def sol11():
    """determines the encryption mode of an algorithm that uses random keys and encrypts randomly under either CBC or ECB mode"""

    test_string = AES_oracle("\x00"*16*6)
    ciph_blocks = [test_string[i*16:(i + 1)*16] for i in range(int(len(test_string)/16))]  
    rep_count = max([test_string.count(a) for a in ciph_blocks])
    if rep_count > 2:
        return 1
    else:
        return 0
def sol12(unknown_string):
    """decodes a string encrypted in AES-128 ECB block mode by appending certain strings to the beginning of the plaintext. """

    #sets a random key for the entire algorithm
    init_key = rand_key(16)

    #Appends an initial block to the original unknown input string
    first_block = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".decode("base64")
 
    unknown_string = first_block + unknown_string

    #Determines block size by first appending repeated blocks of text to the unknown string
    block_size = get_block_size(unknown_string, init_key, 0)    

    print("Detected Block-Size: {}".format(block_size))
    
    #Decrypting oracle by creating dictionary of text-ciphertext values and looking up characters by encrypting user-defined strings appended to thee
    decrypt_string = AES_oracle_decrypt(block_size, init_key, unknown_string)
    
    return decrypt_string

def get_block_size(unknown_string, init_key, init_text_yesno):
    """determines block size from AES-128 ECB oracle"""
    block_test = 0
    counter = 0
    while (block_test != 1):
        counter += 1

        if counter < 4:
            multiple = 10
        else:
            multiple = 4
        if init_text_yesno == 1:
            input_string = "".join(chr(random.randint(1,255)) for i in range(random.randint(1,100))) + "\x00"*multiple*counter + unknown_string
        elif init_text_yesno == 0:
           input_string = "\x00"*multiple*counter + unknown_string
	
        ciph_text = AES_ECB(input_string, init_key)

        ciph_blocks = list(set([ciph_text[i*counter:(i + 1)*counter] for i in range(int(len(ciph_text)/counter))]))
            
        for i in ciph_blocks:                        
            if ciph_text.count(i*(multiple - 1)) > 0:
                block_test = 1

    #At this stage, the block size = counter value
    return counter

def AES_oracle_decrypt(block_size, init_key, unknown_string):
    """decrypts string encrypted with AES_oracle by repeated calls to oracle with appended user-defined strings."""
    

    init_bytes = "A"*(block_size - 1)
    counter = 0
    
    while counter < len(unknown_string):       
        init_string =  "A"*( (block_size - 1) - (counter % block_size))
        test_dict = dict()
        for i in range(256):                        
            test_string = init_bytes[-(block_size - 1):] + chr(i)           
            ciph_text = AES_ECB(test_string, init_key)                                
            test_dict[ciph_text] = chr(i)
        ciph_text = AES_ECB(init_string + unknown_string, init_key)
        ciph_blocks = [ciph_text[block_size*i:block_size*(i + 1)] for i in range(int(len(ciph_text)/block_size))]
        plaintext = test_dict[ciph_blocks[(counter // block_size) ]]	
        print("next byte in text: " + str(ord(plaintext)))
        init_bytes += plaintext
        print(init_bytes)
        counter += 1
    return init_bytes[15:]

def profile_for(email, init_key):
    """returns the object that is defined by a simple email address using uid = 10 and role as user."""
    profile = {"email":email, "uid":10, "role":"user"}
    
    #returns profile in requested format
    profile = "email={}&uid={}&role={}".format(profile["email"], profile["uid"], profile["role"])
    
    #ecrypting key under init_key
    ciph_text = AES_ECB(profile, init_key)
    #print "Cipher Text : {}".format(ciph_text)

    #return ciph_text  
    return ciph_text

def sol13(email, init_key):
    """encrypts a profile generated from an email."""    
        
    #Generate a random initial, 'dummy' key
    #init_key = rand_key(16)

    #Determines offset of user-input within plaintext:
    rep = 1
    counter = 1
    while rep != 0:
        ciph_text = profile_for("\x00"*(48 - counter), init_key)
        ciph_blocks = [ciph_text[16*i:16*(i + 1)] for i in range(int(len(ciph_text)/16))]
        rep = 0
        counter2 = 0

        while ((rep == 0) & (counter2 < (len(ciph_blocks) -1))):
            if ciph_blocks[counter2] == ciph_blocks[counter2 + 1]:
                rep = 1
            counter2 += 1           
        
        counter += 1
	
    offset = counter - 2

    print("offset = {}".format(offset))
    
#NOTE: FROM HERE ON OUT, RELEVANT CHUNKS ARE ASSUMED TO BE THE SECOND CHUNK IN THE CIPHERTEXT. INSTEAD, THIS NUMBER SHOULD BE PROGRAMMATICALLY GENERATED.

    init_bytes = "AAAAAAAAAAAAAAA"
    
    counter = 0
    user_position = 0

    test_user = 1

    #Determine the next block-size of text in the encoded user-profile. 
    while test_user != 0:       
        init_string =  "A"*(15 - (counter % 16))
        test_dict = dict()
        for i in range(256):                        
            email =  (16 - offset)*"A" + init_bytes[-15:] + chr(i)           
            ciph_text = profile_for(email, init_key)
            ciph_blocks = [ciph_text[16*j:16*(j + 1)] for j in range(int(len(ciph_text)/16))]                     
            test_dict[ciph_blocks[1]] = chr(i)
        ciph_text = profile_for((16 - offset)*"A" + init_string, init_key)
        ciph_blocks = [ciph_text[16*i:16*(i + 1)] for i in range(int(len(ciph_text)/16))]
        plaintext = test_dict[ciph_blocks[(counter // 16) + 1]]
        print("next byte in text: " + str(ord(plaintext)))
        init_bytes += plaintext
        print(init_bytes)
        
        #Extract the position of the role= portion of the profile.
        if init_bytes[-5:] == "role=":
            user_position = counter + 1
            test_user = 0
        counter += 1

    #Using the offset value calculated in the previous step, calculate an encrypted chunk that codes the "admin" value that is desired. 
    test_email = (16 - offset)*"A"+ "admin" + 11*"\x00";
    ciph_text = profile_for(test_email, init_key)
    ciph_blocks = [ciph_text[16*i:16*(i + 1)] for i in range(int(len(ciph_text)/16))]
    admin_chunk = ciph_blocks[1]

    print("____________________________________\n")
    print("admin chunk: " + admin_chunk)

    #construct an email which has precisely right number of bytes to place the "admin" portion of the email on a separate block. 
    test_email = "A"*(16 - offset) + "A"*(16 - (user_position % 16))

    #Determine the block number on which the "admin" portion of the profile would start. 
    block_num= (offset + len(test_email) + user_position) // 16 

    print("Block Num : " + str(block_num))

    #Construct the fake admin profile:
    ciph_text = profile_for(test_email, init_key)   
    ciph_blocks = [ciph_text[16*j:16*(j + 1)] for j in range(int(len(ciph_text)/16))]
    ciph_blocks[block_num] = admin_chunk
    admin_ciph = "".join(ciph_blocks)

    return admin_ciph

def sol14(unknown_string, init_key):
    """decodes a string encrypted in AES-128 ECB block mode, with random strings appended to target bytes """

    #sets a random key for the entire algorithm
    init_key = rand_key(16)     

    #Determines block size by first appending repeated blocks of text to the unknown string
    block_size = get_block_size(unknown_string, init_key, 1)    

    print("Detected Block-Size: {}".format(block_size))

    anchor_block = AES_ECB("A"*block_size, init_key)    

    test_dict = dict()

    init_bytes = "A"*(block_size - 1)
     
    #Initializing our test dictionary
    for i in range(256):
        test_dict[AES_ECB(init_bytes[-(block_size - 1):] + chr(i), init_key)] = chr(i)

    test_bytes = "";
    
    counter = 0
    while counter <= len(unknown_string):
        while not test_bytes in test_dict.keys():
            ciph_text = rand_profile("A"*(2*block_size) + unknown_string, init_key)
            ciph_blocks = [ciph_text[block_size*i:block_size*(i + 1)] for i in range(int(len(ciph_text)/block_size))]
            test_bytes = ciph_blocks[ciph_blocks.index(anchor_block) + 1 + (counter//16)]
        
        init_bytes += test_dict[test_bytes]

        print(init_bytes)
        
        #Resetting our test_dictionary based upon what the next character is
        test_dict = dict()

        for i in range(256):
            test_dict[AES_ECB(init_bytes[-(block_size - 1):] + chr(i), init_key)] = chr(i)
       
        counter += 1
        test_bytes = ""

    return init_bytes[16:]
    

def rand_profile(input_string, init_key):
    """encrypts an input_string after first appending a random string with a size smaller than 100 characters using pkcs7 padding"""
    return AES_ECB("".join(chr(random.randint(1,255)) for i in range(random.randint(0,100))) + input_string, init_key)

class PaddingError(Exception):
    """raises an error when there is a padding error"""	
    pass

def sol15(test_string):
    """ Determines if a given string of plaintext has valid pkcs7 padding at the end; throws exception otherwise. """
    if (len(test_string) % 16) != 0:
        raise PaddingError("Test string does not have correct number of bytes")		      
        return
    else:
        padnum = ord(test_string[len(test_string) - 1])
        if padnum*chr(padnum) in test_string:
            if test_string[::-1].index(padnum*chr(padnum)) != 0:
                raise PaddingError("Test string does not have correct padding")
                return
            else:
                return test_string[0:(len(test_string) - padnum)]
        else:
            raise PaddingError("Test string does not have correct padding")
            return

"""-------------------------------------------------------------------------"""


lang_freq = Load_LangMetric("char_freq_english.txt", "\n", string.ascii_lowercase + " ")
                                                                                                                                                            
