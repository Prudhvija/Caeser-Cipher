#!/usr/bin/env python
# coding: utf-8

# In[ ]:


alphabet = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

def caesar(text: str, shift: int, direction: str) -> str:
  multiplier = 0
  if direction == "encode":
    multiplier = 1
  elif direction == "decode":
    multiplier = -1
  else:
    print("No idea, what you are doing, I'm just gonna give you your text back")
  new_text = ""
  for char in text:
    if char not in alphabet:
      new_text += char
      continue
    char_position = alphabet.index(char)
    new_char_position = (char_position + shift * multiplier) % len(alphabet)
    new_text += alphabet[new_char_position]
  return new_text

from art import CEASAR_LOGO
print(CEASAR_LOGO)

while True:
  direction = input("Type 'encode' to encrypt, type 'decode' to decrypt:\n").lower()
  text = input("Type your message:\n").lower()
  shift = int(input("Type the shift number:\n"))
  print(f"Result text is: {caesar(text, shift, direction)}")
  cont_answer = ""
  while cont_answer not in ["yes", "no"]:
    cont_answer = input("Do you wish to continue? 'yes' or 'no' ").lower()
  if cont_answer == 'no':
    break


# In[ ]:


import re

class VigenereCipher(object):

    """
    This class provides methods for enciphering and
    deciphering text using the Vigenere cipher.
    """

    def __init__(self):

        self.tabularecta = self.__create_tabula_recta()

    def __create_tabula_recta(self):

        tabularecta = []

        for r in range(0, 26):

            offset = 0
            row = []

            for column in range(0, 26):
                row.append(chr(r + 65 + offset))
                offset += 1
                if offset > (25 - r):
                    offset = offset - 26

            tabularecta.append(row)

        return tabularecta

    def encipher(self, plaintext, keyword):

        """
        The plaintext argument can be any string, but
        only the letters a-z and A-Z will be included
        in the encrypted text.
        """

        plaintext = self.__process_plaintext(plaintext)
        keywordrepeated = self.__get_keyword_repeated(keyword, len(plaintext))
        ciphertext = []

        for index, letter in enumerate(plaintext):

            plaintextindex = ord(letter.upper()) - 65
            keywordindex = ord(keywordrepeated[index]) - 65

            #--------------------#
            # Using tabula recta #
            #--------------------#
            encipheredletter = self.tabularecta[keywordindex][plaintextindex]

            #---------------#
            # Using algebra #
            #---------------#
            # encipheredletter = chr(((plaintextindex + keywordindex) % 26) + 65)

            ciphertext.append(encipheredletter)

        return "".join(ciphertext)

    def decipher(self, ciphertext, keyword):

        """
        Decrypts the ciphetext using the keyword.
        Only the letters a-z and A-Z in the
        original text will be present in the
        decrypted text.
        """

        keywordrepeated = self.__get_keyword_repeated(keyword, len(ciphertext))
        decipheredtext = []

        for index, letter in enumerate(ciphertext):

            keywordindex = ord(keywordrepeated[index]) - 65

            #--------------------#
            # Using tabula recta #
            #--------------------#
            decipheredletter = chr(self.tabularecta[keywordindex].index(letter) + 65)

            #---------------#
            # Using algebra #
            #---------------#
            # decipheredletter = chr((((ord(letter) - 65) - keywordindex) % 26) + 65)

            decipheredtext.append(decipheredletter)

        return "".join(decipheredtext)

    def __process_plaintext(self, plaintext):

        plaintext = plaintext.upper()
        plaintext = re.sub("[^A-Z]", "", plaintext)

        return plaintext

    def __get_keyword_repeated(self, keyword, length):

        keyword = keyword.upper()
        keywordrepeated = []
        keywordlength = len(keyword)
        keywordindex = 0

        for i in range(0, length):
            keywordrepeated.append(keyword[keywordindex])
            keywordindex += 1
            if keywordindex > keywordlength - 1:
                keywordindex = 0

        return "".join(keywordrepeated)


# In[ ]:


def generateKey(string, key): 
  key = list(key) 
  if len(string) == len(key): 
    return(key) 
  else: 
    for i in range(len(string) -len(key)): 
      key.append(key[i % len(key)]) 
  return("" . join(key)) 
  
def encryption(string, key): 
  encrypt_text = [] 
  for i in range(len(string)): 
    x = (ord(string[i]) +ord(key[i])) % 26
    x += ord('A') 
    encrypt_text.append(chr(x)) 
  return("" . join(encrypt_text)) 

def decryption(encrypt_text, key): 
  orig_text = [] 
  for i in range(len(encrypt_text)): 
    x = (ord(encrypt_text[i]) -ord(key[i]) + 26) % 26
    x += ord('A') 
    orig_text.append(chr(x)) 
  return("" . join(orig_text)) 

if __name__ == "__main__": 
  string = input("Enter the message: ")
  keyword = input("Enter the keyword: ")
  key = generateKey(string, keyword) 
  encrypt_text = encryption(string,key) 
  print("Encrypted message:", encrypt_text) 
  print("Decrypted message:", decryption(encrypt_text, key)) 


# In[ ]:




