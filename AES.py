from polynomial import *
import numpy as np

def word_rotate(test_string):
    """takes a 4-character string and rotates it one byte to the left. """
    error_msg = "\n word_rotate: input must be 4-character string \n"
    if len(test_string) != 4:
        print(error_msg)
        return                    
    else:
        test_list = list(test_string)
        return "".join(test_list[(i + 1) % 4] for i in range(4))

def rcon(n):
    """returns the rijndael rcon function evaluated at the nth round"""
    return int("".join(str(a) for a in poly_div(xpow(n - 1), [1,1,0,1,1,0,0,0,1], 2)[1][::-1]), 2)

def log_table():
    """returns the logarithm table for elements of the rijndael field """
    """uses x + 1 as the generator for the rijndael field """
    lookup = [[]]*(2**8)
    lookup_r = [[]]*(2**8)
    poly = [1]
    lookup[0] = [0, poly]
    lookup_r[0] = [0, 1]
    for i in range(255):
        poly = poly_div(poly_mult(poly, [1,1], 2), [1, 1, 0, 1, 1, 0, 0, 0, 1], 2)[1]
        lookup[i + 1] = [i + 1, poly]
        lookup_r[i + 1] = [i + 1, int("".join(str(a) for a in poly)[::-1], 2)] 
    lookup_r = np.array(lookup_r)   
    lookup_r = lookup_r[lookup_r[:,1].argsort()]
    return [list(a) for a in lookup_r]
    
def mult_inverse(poly, power_table, field_size):
    """Computes the inverse of a given element in the rijndael field, using the lookup table power table """
    """Note: generator is taken to be the element x + 1 in the rijndael field. """
    power = power_table[int(poly, 2)][0]
    inv_power = field_size - power
    power_table_r = np.array(power_table)
    power_table_r = power_table_r[power_table_r[:,0].argsort()]
    if poly.count("1") != 0:
        inv = [int(a) for a in list(bin(power_table_r[inv_power][1])[2:].zfill(8)[::-1])]
    else:
        inv = [0, 0, 0, 0, 0, 0, 0, 0]
    return inv

def S_box(test_string):	
    """returns the S-box of the test_string by operating on each byte"""
    """First we must compute the multiplicative inverse in the rijndael field. """
    const = np.array([1, 1, 0, 0, 0, 1, 1, 0])
    matrix = np.array([[1, 0, 0, 0, 1, 1, 1, 1], [1, 1, 0, 0, 0, 1, 1, 1], [1, 1, 1, 0 ,0 ,0, 1, 1], [1, 1, 1, 1, 0 ,0 ,0, 1], [1, 1, 1, 1, 1, 0, 0, 0], [0, 1, 1, 1, 1, 1, 0, 0], [0, 0, 1, 1, 1, 1, 1, 0], [0, 0, 0, 1, 1, 1, 1, 1]])
    test_string_r = [0]*len(test_string)
    test_string = [format(ord(x),"b").zfill(8) for x in test_string]
    for i in range(len(test_string)):
        inv = np.array(mult_inverse(test_string[i], power_table, 255))
        inv = np.add(np.dot(matrix, inv), const)
        test_string_r[i] = int("".join(str(a % 2) for a in list(inv)[::-1]), 2)
    return test_string_r

def expanded_key(AES_size, init_key):
    """Returns the expanded key of the algorithm"""
    """init_key is a string of characters (bytes) which form the initial key"""
    
    if AES_size == 128:        
        nk = 4
        nb = 4
        nr = 10
    elif AES_size == 192:
        nk = 6
        nb = 4
        nr = 12
    elif AES_size == 256:        
        nk = 8
        nb = 4
        nr = 14

    exp_key = [""]*nb*(nr + 1)  	 

    for i in range(nk):
        exp_key[i] = init_key[(4*i):(4*i + 4)]
    
    i = nk
    
    while i < nb*(nr + 1):
        temp = exp_key[i - 1]
        if i % nk == 0:
            temp = "".join(chr(S_box(word_rotate(temp))[j]^[rcon(int(i/nk)), 0, 0, 0][j]) for j in range(4))
        elif (nk > 6 and (i % nk == 4)):
            temp = [chr(a) for a in S_box(temp)]
        exp_key[i] = "".join(chr(ord(exp_key[i - nk][j])^ord(temp[j])) for j in range(4))
        i += 1

    return exp_key

def obtain_state(AES_size, input_string):
    """loads the input string of characters into the AES state """
    """NOTE: input string must be a string of 128 bits (16 bytes) """
    
    if AES_size == 128:        
        nk = 4
        nb = 4
        nr = 10
    elif AES_size == 192:
        nk = 6
        nb = 4
        nr = 12
    elif AES_size == 256:        
        nk = 8
        nb = 4
        nr = 14

    state = [[]]*4

    for r in range(4):
        state[r] = list(input_string[r::4])

    return state

def obtain_string(AES_size, input_state):
    """loads the input string of characters into the AES state """
    """NOTE: input string must be a string of 128 bits (16 bytes) """
    
    if AES_size == 128:        
        nk = 4
        nb = 4
        nr = 10
    elif AES_size == 192:
        nk = 6
        nb = 4
        nr = 12
    elif AES_size == 256:        
        nk = 8
        nb = 4
        nr = 14

    output_string = [""]*4*nb

    for r in range(4):
        for c in range(nb):
            output_string[r + 4*c] = input_state[r][c]

    return "".join(output_string)

def transpose(state):
    return [[x[i] for x in state] for i in range(len(state[0]))]
        

def AddRoundKey(state, round_key):
    """ bitwise-xor's the round key with the state in the AES standard """
    return [[chr(ord(x[j])^ord(round_key[i][j])) for j in range(4)] for i,x in enumerate(state)]

def ShiftRows(state):
    """returns the shifted rows of the state"""
    for i in range(len(state)):
        state[i] = [state[i][(j + i) % len(state[i])] for j in range(len(state[i]))]
    return state

def InvShiftRows(state):
    """returns the inverted shiftrows transformation of the AES standard"""
    for i in range(len(state)):
        state[i] = [state[i][(j + 3*i) % len(state[i])] for j in range(len(state[i]))]
    return state

def InvS_box(test_string):
    """returns the inverse s-box of any given string"""

    const = np.array([1, 1, 0, 0, 0, 1, 1, 0])

    matrix = np.array([[0, 0, 1, 0, 0, 1, 0, 1], [1, 0, 0, 1, 0, 0, 1, 0], [0, 1, 0, 0, 1, 0, 0, 1], [1, 0, 1, 0, 0, 1, 0, 0], [0, 1, 0, 1, 0, 0, 1, 0], [0, 0, 1, 0, 1, 0, 0, 1], [1, 0, 0, 1, 0, 1, 0, 0], [0, 1, 0, 0, 1, 0, 1, 0]])    

    test_string_r = [[]]*len(test_string)      
    
    for i in range(len(test_string)):        
        inv = np.array([int(a) for a in list(format(ord(test_string[i]), "b").zfill(8)[::-1])])        
        inv = list(np.dot(matrix, np.add(inv, const)))        
        test_string_r[i] = "".join(str(a) for a in mult_inverse("".join([str(a % 2) for a in inv[::-1]]), power_table, 255))[::-1]

    test_string_r = "".join(chr(int(a, 2)) for a in test_string_r)
    
    return test_string_r

def InvMixColumns(column):
    """performs the inverse mix_columns function of the standard AES implementation, column here is a list of 4 bytes"""

    column = [[int(a) for a in list(bin(ord(x))[2:].zfill(8)[::-1])] for x in column]
    
    new_column = [""]*4

    new_column[0] = chr(int("".join(str(a) for a in poly_div(poly_add(poly_add(poly_add(poly_mult([0, 1, 1, 1, 0, 0, 0, 0], column[0], 2), poly_mult([1, 1, 0, 1, 0, 0, 0, 0], column[1], 2), 2), poly_mult(column[2], [1, 0, 1, 1, 0, 0, 0, 0], 2), 2), poly_mult(column[3], [1, 0, 0, 1, 0, 0, 0, 0], 2), 2), [1, 1, 0, 1, 1, 0, 0, 0, 1], 2)[1][::-1]), 2))

    new_column[1] = chr(int("".join(str(a) for a in poly_div(poly_add(poly_add(poly_add(poly_mult([0, 1, 1, 1, 0, 0, 0, 0], column[1], 2), poly_mult([1, 1, 0, 1, 0, 0, 0, 0], column[2], 2), 2), poly_mult(column[3], [1, 0, 1, 1, 0, 0, 0, 0], 2), 2), poly_mult(column[0], [1, 0, 0, 1, 0, 0, 0, 0], 2), 2), [1, 1, 0, 1, 1, 0, 0, 0, 1], 2)[1][::-1]), 2))

    new_column[2] = chr(int("".join(str(a) for a in poly_div(poly_add(poly_add(poly_add(poly_mult([0, 1, 1, 1, 0, 0, 0, 0], column[2], 2), poly_mult([1, 1, 0, 1, 0, 0, 0, 0], column[3], 2), 2), poly_mult(column[0], [1, 0, 1, 1, 0, 0, 0, 0], 2), 2), poly_mult(column[1], [1, 0, 0, 1, 0, 0, 0, 0], 2), 2), [1, 1, 0, 1, 1, 0, 0, 0, 1], 2)[1][::-1]), 2))

    new_column[3] = chr(int("".join(str(a) for a in poly_div(poly_add(poly_add(poly_add(poly_mult([0, 1, 1, 1, 0, 0, 0, 0], column[3], 2), poly_mult([1, 1, 0, 1, 0, 0, 0, 0], column[0], 2), 2), poly_mult(column[1], [1, 0, 1, 1, 0, 0, 0, 0], 2), 2), poly_mult(column[2], [1, 0, 0, 1, 0, 0, 0, 0], 2), 2), [1, 1, 0, 1, 1, 0, 0, 0, 1], 2)[1][::-1]), 2))

    return new_column
    

def MixColumns(column):
    """performs the mix_columns function of the standard AES implementation, column here is a list of 4 bytes"""
    column = [[int(a) for a in list(bin(ord(x))[2:].zfill(8)[::-1])] for x in column]
    
    new_column = [""]*4

    new_column[0] = chr(int("".join(str(a) for a in poly_div(poly_add(poly_add(poly_add(poly_mult([0, 1, 0, 0 ,0, 0, 0, 0], column[0], 2), poly_mult([1, 1, 0, 0, 0, 0, 0, 0], column[1], 2), 2), column[2], 2), column[3], 2), [1, 1, 0, 1, 1, 0, 0, 0, 1], 2)[1][::-1]), 2))

    new_column[1] = chr(int("".join(str(a) for a in poly_div(poly_add(poly_add(poly_add(poly_mult([0, 1, 0, 0 ,0, 0, 0, 0], column[1], 2), poly_mult([1, 1, 0, 0, 0, 0, 0, 0], column[2], 2), 2), column[3], 2), column[0], 2), [1, 1, 0, 1, 1, 0, 0, 0, 1], 2)[1][::-1]), 2))

    new_column[2] = chr(int("".join(str(a) for a in poly_div(poly_add(poly_add(poly_add(poly_mult([0, 1, 0, 0 ,0, 0, 0, 0], column[2], 2), poly_mult([1, 1, 0, 0, 0, 0, 0, 0], column[3], 2), 2), column[0], 2), column[1], 2), [1, 1, 0, 1, 1, 0, 0, 0, 1], 2)[1][::-1]), 2))

    new_column[3] = chr(int("".join(str(a) for a in poly_div(poly_add(poly_add(poly_add(poly_mult([0, 1, 0, 0 ,0, 0, 0, 0], column[3], 2), poly_mult([1, 1, 0, 0, 0, 0, 0, 0], column[0], 2), 2), column[1], 2), column[2], 2), [1, 1, 0, 1, 1, 0, 0, 0, 1], 2)[1][::-1]), 2))    

    return new_column

def FIPS_format(state):
    """formats according to the FIPS format (AES standard pdf 1971)"""
    return [[y.encode("hex") for y in state[i]] for i in range(len(state))]

def cipher(AES_size, input_string, init_key):
    """returns the output of AES algorithm given an input string and an intial key. """

    if AES_size == 128:        
        nk = 4
        nb = 4
        nr = 10
    elif AES_size == 192:
        nk = 6
        nb = 4
        nr = 12
    elif AES_size == 256:        
        nk = 8
        nb = 4
        nr = 14   

    exp_key = expanded_key(AES_size, init_key)

    state = obtain_state(AES_size, input_string)
    #print FIPS_format(state)

    state = transpose(AddRoundKey(transpose(state), exp_key[0:nb]))
    #print FIPS_format(state)

    for i in range(nr - 1):
        state = [[chr(s) for s in S_box("".join(x))] for x in state]
        #print FIPS_format(state)

        state = ShiftRows(state)
        #print FIPS_format(state)

        state = transpose([MixColumns(x) for x in transpose(state)])
        #print FIPS_format(state)

        state = transpose(AddRoundKey(transpose(state), exp_key[(i + 1)*nb:(i + 2)*nb]))
        #print FIPS_format(state)

    state = [[chr(s) for s in S_box("".join(x))] for x in state]
    #print FIPS_format(state)

    state = ShiftRows(state)
    #print FIPS_format(state)

    state = transpose(AddRoundKey(transpose(state), exp_key[nr*nb:(nr + 1)*nb]))
    #print FIPS_format(state)

    ciphertext = obtain_string(128, state)

    return ciphertext   

def InvCipher(AES_size, input_string, init_key):
    """Returns the plaintext, given the ciphertext output of the AES algorithm."""

    if AES_size == 128:        
        nk = 4
        nb = 4
        nr = 10
    elif AES_size == 192:
        nk = 6
        nb = 4
        nr = 12
    elif AES_size == 256:        
        nk = 8
        nb = 4
        nr = 14   

    exp_key = expanded_key(AES_size, init_key)
 
    """state in this case is the equivalent ciphertext."""
    state = obtain_state(AES_size, input_string)
    #print FIPS_format(state)

    state = transpose(AddRoundKey(transpose(state), exp_key[nr*nb:nb*(nr + 1)]))
    #print FIPS_format(state)

    for i in range(nr - 1, 0, -1):
        
        round_key = ["".join(x) for x in [InvMixColumns(x) for x in [list(x) for x in exp_key[i*nb:(i + 1)*nb]]]]
        
        state = [list(InvS_box("".join(x))) for x in state]
        #print FIPS_format(state)
	
        state = InvShiftRows(state)
        #print FIPS_format(state)

        state = transpose([InvMixColumns(x) for x in transpose(state)])
        #print FIPS_format(state)
        
        state = transpose(AddRoundKey(transpose(state), round_key))
        #print FIPS_format(state)

    state = [list(InvS_box("".join(x))) for x in state]
    #print FIPS_format(state)

    state = InvShiftRows(state)
    #print FIPS_format(state)

    """round_key = ["".join(x) for x in [InvMixColumns(x) for x in [list(x) for x in exp_key[0:nb]]]]"""

    state = transpose(AddRoundKey(transpose(state), exp_key[0:nb]))
    #print FIPS_format(state)

    plaintext = obtain_string(128, state)

    return plaintext


power_table = log_table()
