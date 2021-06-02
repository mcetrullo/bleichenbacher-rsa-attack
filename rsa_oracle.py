import conversions
import random 
import math 

class Server:
    #---- Constructor to maintain state of keys and such 
    def __init__(self): 
        # RSA compliant modulus
        self.N = 769004561718333719775140505903813141987368589603134112471732845900545648826400786550253012051239062153025964014521822895242220908146707985069313398169175356585169550035124607516609776067593453120241561474304303123458554258728545978366311938916851557998103981406415920953405412252011236871476753840319541573
        # bit size of key 
        self.keysize = 128
        # encryption exponent
        self.e = 5
        # decryption exponent 
        self.d = 461402737031000231865084303542287885192421153761880467483039707540327389295840471930151807230743437291815578408713093737145332544888024791041588038901500359588187290865464071412773728192229998953365128385041521765765976071995639771606490742471919078239671848843394957575718298328771638144625266571976491873
        # private and public keys 
        self.privatekey = (self.d,self.N)
        self.publickey = (self.e,self.N)

    #---- This public function sends the public key to they 'Hacker' 
    def send_publickey(self):
        return(self.publickey)

    #---- This private function pads the message 
    def __pad_message(self,message):
        # The length of the padding conforms to the padding scheme of PKCS#1 
        pad_len = self.keysize-len(message)-3
        random_padding = b''
        # Adds random non-zero byte to the padding scheme
        for i in range (0,pad_len):
            random_padding+=bytes([random.randint(1, 255)])
        # Completes and returns padded message
        padded_message = b'\x00\x02' + random_padding + b'\x00' + message
        return padded_message

    #---- This sends an encrypted message to the 'Hacker'
    def get_message(self):
        message = b'This is an encrypted message!'
        padded_message = self.__pad_message(message)
        padded_message = conversions.bytes_to_int(padded_message)
        encryption = pow(padded_message,self.e, self.N)
        return encryption

    #---- This is where the hacker sends their message and operates as a padding oracle
    def oracle(self,cipher):
        # The 'Hacker' sends an integer, and we will use the private decryption exponent to decrypt
        message = pow(cipher,self.d,(self.N))
        # Convert the message to a bytes object 
        message = conversions.int_to_bytes(message)
        # to handle zeros in the front of integer/message 
        # basically append it back on
        if len(message)<self.keysize:
            message = b'\x00'*(self.keysize-len(message)) + message
        if message[0] == 0 and message[1] == 2:
            return True
        else:
            return False


class Hacker(Server):
    #---- Constructor 
    def __init__(self): 
        Server.__init__(self)
        self.key = None
        self.B = None
        self.intervals = []
        self.s = None
        self.message = None
    
    #---- Gets public key from the 'Server'
    def get_key(self):
        self.key = self.send_publickey()
        print("The public key is: ", self.key)
        

    #---- Gets encrypted message from server and saves the state
    def recieve_message(self):
        self.message = self.get_message()
        print("The encrypted message is: ", self.message)
        
    #---- Calculates B
    def get_B(self):
        k = len(conversions.int_to_bytes(self.key[1]))
        self.B = 2**(8*(k-2))
        
    #---- Returns the starting interval (for simplicity)
    def get_m0(self):
        self.intervals.append((2*self.B,(3*self.B)-1))

    #---- Step2a as outlined in the Bleichenbacher paper
    def step2a(self):
        valid = False
        # starting value for s is N/3B
        self.s = math.ceil(self.key[1]/(3*self.B))
        
        # This loop incrememnts s checking in with the oracle each time
        while valid == False:
            c_prime = (self.message*(pow(self.s,self.key[0],self.key[1])))%self.key[1]
            valid  = self.oracle(c_prime)
            if valid == False:
                self.s+=1

    #---- Step 2b as outlined in the Bleichenbacher paper
    def step2b(self):
        valid = False
        # starting search for next s 
        self.s +=1
        # follow same steps as step 2a
        while valid == False:
            c_prime = (self.message*(pow(self.s,self.key[0],self.key[1])))%self.key[1]
            valid  = self.oracle(c_prime)
            if valid == False:
                self.s+=1

    #---- Step 2c as outlined in the Bleichenbacher paper
    def step2c(self):
        # find starting point for r
        r = math.ceil(2*(((self.intervals[0][1]*self.s)- (2*self.B))/self.key[1]))
        valid = False
        while valid == False:
            # find upper and lower bounds for new s 
            lower = (((2*self.B) + (r*self.key[1]))//self.intervals[0][1])+1
            upper = ((3*self.B)+(r*self.key[1]))//self.intervals[0][0]
            # search for next s value
            for i in range(lower,upper+1):
                c_prime = (self.message*(pow(i,self.key[0],self.key[1])))%self.key[1]
                valid  = self.oracle(c_prime)
                # break out of the loop once a valid s is found
                if valid == True:
                    self.s = i
                    break
            r+=1

    #---- Step 3 as outlined in the Bleichenbacher paper
    #---- This step finds the intervals for the next iteration
    def step3(self):
        # initialize a spot to keep the new intervals (M_i)
        new_intervals = []
        # go through all intervals
        for i in self.intervals:

            # calculate range of r's
            lower = (((i[0]*self.s)-((3*self.B)+1))//self.key[1])+1
            upper = ((i[1]*self.s)-(2*self.B)//self.key[1])
            # calculate each interval that is in the range of r's
            for r in range(lower,upper+1):
                a = max(i[0],(((2*self.B)+(r*self.key[1]))//self.s)+1)
                b = min(i[1],(((3*self.B)-1)+(r*self.key[1]))//self.s)
                # check and make sure it is a valid and not already covered interval
                if b >= a :
                    if (a,b) not in new_intervals:
                        new_intervals.append((a,b))
                # This is the criteria to break out of the loop, since no new intervals will be revealed
                elif a != i[0] and b == i[1] and a>b:
                    break
                
        # if a new interval isn't found, maintain the old interval
        if new_intervals:
            self.intervals = new_intervals

     #---- Step 4 as outlined in the Bleichenbacher paper
    def step4(self):
        m = conversions.int_to_bytes(self.intervals[0][0])
        for i in range(2,len(m)):
            if m[i]==0:
                unpad = i+1
                break
        return m[unpad:]
 
    #---- Uses all outlined functions to perform the attack
    def attack(self):
        # Get the public key from the server
        self.get_key()
        # Get the encrypted message from the server
        self.recieve_message()
        # Calculate 'B'
        self.get_B()
        # Get initial interval
        self.get_m0()
        # Start search
        self.step2a()
        # get next intervals
        hacker.step3()
        # Check and make sure the first set of intervals are not the solution
        if self.intervals[0][0]==self.intervals[0][1]:
            return self.step4()
        # Otherwise enter loop
        while True:
            if len(hacker.intervals) == 1:
                hacker.step2c()
            else:
                hacker.step2b()
            hacker.step3()
            if len(hacker.intervals)==1 and hacker.intervals[0][0]==hacker.intervals[0][1]:
                break
        return self.step4()
        
    

# DRIVING CODE
hacker = Hacker()
print( "The Recovered message is: " , hacker.attack())
