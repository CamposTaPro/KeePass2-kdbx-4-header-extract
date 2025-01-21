import struct
import argparse

def bytes_to_mib(byte_value):
    return byte_value / (1024 * 1024)  # Divide by 2^20 (1,048,576)

def main():
    parser = argparse.ArgumentParser(description="Read and parse a KDBX file.")
    parser.add_argument("filename", type=str, help="Path to the KDBX file to be read.")
    args = parser.parse_args()

    data, varientMapData=readFile(args.filename)
    print_values(data,varientMapData)

def read_fixed_size(file, size, unpack_format=None, hex_output=False):
    data = file.read(size)
    if unpack_format:
        return struct.unpack(unpack_format, data)[0]
    if hex_output:
        return data.hex()
    return data

def read_fixed_size_string(file,size):
    data = file.read(size)
    return data.decode("utf-8")

def read_varientMap(file):

    varientDictionaryFormat=read_fixed_size(file,2,"<H")
    #print(hex(varientDictionaryFormat))
    uuidKDFType= file.read(1) # not used for anything but it still needs to be read
    uuidKDFNameSize=read_fixed_size(file,4,"<I")
    #print(uuidKDFNameSize)
    uuidKDFName=read_fixed_size_string(file,uuidKDFNameSize)
    #print(uuidKDFName)
    uuidKDFValueSize=read_fixed_size(file,4,"<I")
    #print(uuidKDFValueSize)
    uuidKDFValue=read_fixed_size(file,uuidKDFValueSize,None,True)
    #print(uuidKDFValue)
    if uuidKDFValue in ["ef636ddf8c29444b91f7a9a403e30a0c","9e298b1956db4773b23dfc3ec6f0a1e6"]:
        kdf=1             #this variable is only to help distiguish the KDFs -> 1 - argon2d or argon2id and 2 - AES-KDF
        ######## For entry I (Iterations)  ##################
        argon2IterationType= file.read(1)
        argon2IterationNameSize=read_fixed_size(file,4,"<I")
        #print(argon2IterationNameSize)
        argon2IterationName=read_fixed_size_string(file,argon2IterationNameSize)
        #print(argon2IterationName)
        argon2IterationValueSize=read_fixed_size(file,4,"<I")
        #print(argon2IterationValueSize)
        argon2IterationValue=read_fixed_size(file,argon2IterationValueSize,"<Q")
        #print(argon2IterationValue)
        ######## For entry M (Memory)  ##################
        argon2MemoryType= file.read(1)
        argon2MemoryNameSize=read_fixed_size(file,4,"<I")
        #print(argon2MemoryNameSize)
        argon2MemoryName=read_fixed_size_string(file,argon2MemoryNameSize)
        #print(argon2MemoryName)
        argon2MemoryValueSize=read_fixed_size(file,4,"<I")
        #print(argon2MemoryValueSize)
        argon2MemoryValue=read_fixed_size(file,argon2MemoryValueSize,"<Q")
        #print(argon2MemoryValue)
        ######## For entry P (Parallelism)  ##################
        argon2ParallelismTypeByte= file.read(1)
        argon2ParallelismNameSize=read_fixed_size(file,4,"<I")
        #print(argon2ParallelismNameSize)
        argon2ParallelismName=read_fixed_size_string(file,argon2ParallelismNameSize)
        #print(argon2ParallelismName)
        argon2ParallelismValueSize=read_fixed_size(file,4,"<I")
        #print(argon2ParallelismValueSize)
        argon2ParallelismValue=read_fixed_size(file,argon2ParallelismValueSize,"<I")
        #print(argon2ParallelismValue)
        ######## For entry S (Salt)  ##################
        argon2SaltTypeByte= file.read(1)
        argon2SaltNameSize=read_fixed_size(file,4,"<I")
        #print(argon2SaltNameSize)
        argon2SaltName=read_fixed_size_string(file,argon2SaltNameSize)
        #print(argon2SaltName)
        argon2SaltValueSize=read_fixed_size(file,4,"<I")
        #print(argon2SaltValueSize)
        argon2SaltValue=read_fixed_size(file,argon2SaltValueSize,None,True)
        #print(argon2SaltValue)
        ######## For entry V (Version)  ##################
        argon2VersionTypeByte= file.read(1)
        argon2VersionNameSize=read_fixed_size(file,4,"<I")
        #print(argon2VersionNameSize)
        argon2VersionName=read_fixed_size_string(file,argon2VersionNameSize)
        #print(argon2VersionName)
        argon2VersionValueSize=read_fixed_size(file,4,"<I")
        #print(argon2VersionValueSize)
        argon2VersionValue=read_fixed_size(file,argon2VersionValueSize,"<I",True)
        #print(hex(argon2VersionValue))
        ######## Check for end of VariantMap ##################
        checkEnd=read_fixed_size(file,1,None,True)
        #print(checkEnd)
        data={
            "varientDictionaryFormat": hex(varientDictionaryFormat),
            "uuidKDFValueSize":uuidKDFValueSize,
            "uuidKDFName":uuidKDFName,
            "uuidKDFValueSize":uuidKDFValueSize,
            "uuidKDFValue":uuidKDFValue,
            "argon2IterationValueSize":argon2IterationValueSize,
            "argon2IterationName":argon2IterationName,
            "argon2IterationValue":argon2IterationValue,
            "argon2MemoryValueSize":argon2MemoryValueSize,
            "argon2MemoryName":argon2MemoryName,
            "argon2MemoryValue":argon2MemoryValue,
            "argon2ParallelismValueSize":argon2ParallelismValueSize,
            "argon2ParallelismName":argon2ParallelismName,
            "argon2ParallelismValue":argon2ParallelismValue,
            "argon2SaltValueSize":argon2SaltValueSize,
            "argon2SaltName":argon2SaltName,
            "argon2SaltValue":argon2SaltValue,
            "argon2VersionValueSize":argon2VersionValueSize,
            "argon2VersionName":argon2VersionName,
            "argon2VersionValue":hex(argon2VersionValue),
            "checkEnd":checkEnd,
            "kdf":kdf}
    else:
        #TODO
        kdf=2
        ######## For entry R (Rounds)  ##################
        aesRoundsType= file.read(1)
        aesRoundsNameSize=read_fixed_size(file,4,"<I")
        aesRoundsName=read_fixed_size_string(file,aesRoundsNameSize)
        #print(aesRoundsName)
        aesRoundsValueSize=read_fixed_size(file,4,"<I")
        #print(aesRoundsValueSize)
        aesRoundsValue=read_fixed_size(file,aesRoundsValueSize,"<Q")
        #print(aesRoundsValue)
        ######## For entry S (Salt/seed)  ##################
        aesSaltType= file.read(1)
        aesSaltNameSize=read_fixed_size(file,4,"<I")
        aesSaltName=read_fixed_size_string(file,aesSaltNameSize)
        #print(aesSaltName)
        aesSaltValueSize=read_fixed_size(file,4,"<I")
        #print(aesSaltValueSize)
        aesSaltValue=read_fixed_size(file,aesSaltValueSize,None,True)
        #print(aesSaltValue)
        ######## Check for end of VariantMap ##################
        checkEnd=read_fixed_size(file,1,None,True)
        #print(checkEnd)
        data={
            "varientDictionaryFormat": hex(varientDictionaryFormat),
            "uuidKDFValueSize":uuidKDFValueSize,
            "uuidKDFName":uuidKDFName,
            "uuidKDFValueSize":uuidKDFValueSize,
            "uuidKDFValue":uuidKDFValue,
            "kdf":kdf,
            "aesRoundsName":aesRoundsName,
            "aesRoundsValueSize":aesRoundsValueSize,
            "aesRoundsValue":aesRoundsValue,
            "aesSaltName":aesSaltName,
            "aesSaltValueSize":aesSaltValueSize,
            "aesSaltValue":aesSaltValue,
            "checkEnd":checkEnd
        }
    return data




def readFile(path_file):
    with open(str(path_file), "rb") as file: #teste123.kdbx - AES  Passwords.kdbx- argon2d
        ######## Read Signtures ##################
        signature1=read_fixed_size(file,4,"<I")
        #print(hex(signature1))
        signature2=read_fixed_size(file,4,"<I")
        #print(hex(signature2))
        signature={
            "signature1":hex(signature1),
            "signature2":hex(signature2)
        }
        ######## Read Version of the kdbx file ##################
        minor_version = read_fixed_size(file, 2, "<H")
        major_version = read_fixed_size(file, 2, "<H")
        version = f"{major_version}.{minor_version}"

        #print(version)
        ######## Read the ID of the algorithm used to cipher ##################
        CipherIDFlag=read_fixed_size(file,1,"<B")
        #print(CipherIDFlag)
        CipherIDSize=read_fixed_size(file,4,"<I")
        #print(CipherIDSize)
        CipherID=read_fixed_size(file,CipherIDSize,None,True)# important usar o .hex() quando so quero extrair o valor hexadecimal
        #print(CipherID)
        cipher={
            "CipherIDFlag":CipherIDFlag,
            "CipherIDSize": CipherIDSize,
            "CipherID": CipherID
        }
        #print(cipher)
        ######## Read the compression algorithm used ##################
        compressionFlag=read_fixed_size(file,1,"<B")
        #print(compressionFlag)
        compressionSize=read_fixed_size(file,4,"<I")
        #print(compressionSize)
        compression=read_fixed_size(file,compressionSize,"<I")
        #print(compression)
        compressionAlgorithm={
            "compressionFlag":compressionFlag,
            "compressionSize":compressionSize,
            "compression":compression
        }
        #print(compressionAlgorithm)
        ######## Read the salt used for computing the keys ##################
        saltFlag=read_fixed_size(file,1,"<B")
        #print(saltFlag)
        saltSize=read_fixed_size(file,4,"<I")
        #print(saltSize)
        salt=read_fixed_size(file,saltSize,None,True)
        #print(salt)
        saltData={
            "saltFlag":saltFlag,
            "saltSize":saltSize,
            "salt":salt
        }
        #print(saltData)
        ######## Read the initialization vector for the encryption algorithm. ##################
        encryptionIVFlag=read_fixed_size(file,1,"<B")
        #print(encryptionIVFlag)
        encryptionIVSize=read_fixed_size(file,4,"<I")
        #print(encryptionIVSize)
        encryptionIV=read_fixed_size(file,encryptionIVSize,None,True)# means the encryption algorithm is AES meaning this field is 16 bytes long
        #print(encryptionIV)
        encryptionInitializationVector={
            "encryptionIVFlag":encryptionIVFlag,
            "encryptionIVSize":encryptionIVSize,
            "encryptionIV":encryptionIV
        }
        #print(encryptionInitializationVector)
        ######## Read the parameters for the key derivation function (KDF) ##################
        kdfParamFlag=read_fixed_size(file,1,"<B")
        #print(kdfParamFlag)
        kdfParamSize=read_fixed_size(file,4,"<I")
        #print(kdfParamSize)
        kdfParameters={
            "kdfParamFlag":kdfParamFlag,
            "kdfParamSize":kdfParamSize
        }
       # print(kdfParameters)
        ######## Read the varient map field ##################
        varientMapData=read_varientMap(file)
        ######## Check for end of Headers ##################
        headerEndFlag=read_fixed_size(file,1,"<B")
        #print(headerEndFlag)
        headerEndSize=read_fixed_size(file,4,"<I")
        #print(headerEndSize)
        headerEnd=read_fixed_size(file,headerEndSize,"<I")
        #print(hex(headerEnd))
    data={
        "signature":signature,
        "version":version,
        "cipher":cipher,
        "compressionAlgorithm":compressionAlgorithm,
        "saltData":saltData,
        "encryptionInitializationVector":encryptionInitializationVector,
        "kdfParameters":kdfParameters,
        "headerEndFlag":headerEndFlag,
        "headerEndSize":headerEndSize,
        "headerEnd":hex(headerEnd)
    }
    return data, varientMapData

def print_values(data,vmdata):

    print("Value of the first signature (uint32, little-endian):", data['signature']['signature1'])

    print("Value of the second signature (uint32, little-endian):", data['signature']['signature2'])

    print("Format version:",data['version'])

    if data['encryptionInitializationVector']['encryptionIVSize']==16:
        print("ID",data['cipher']['CipherIDFlag'],"Encryption algorithm - AES-256 (size",data['cipher']['CipherIDSize'],"bytes):",data['cipher']['CipherID'],"(hexdecimal)")
    else:
        print("ID",data['cipher']['CipherIDFlag'],"Encryption algorithm - ChaCha20 (size",data['cipher']['CipherIDSize'],"bytes):",data['cipher']['CipherID'],"(hexdecimal)")

    if data['compressionAlgorithm']['compression']==1:
        print("ID",data['compressionAlgorithm']['compressionFlag'],"Compression algorithm (size",data['compressionAlgorithm']['compressionSize'],"bytes):",data['compressionAlgorithm']['compression'], "(using GZIP)")
    else:
        print("ID",data['compressionAlgorithm']['compressionFlag'],"Compression algorithm (size",data['compressionAlgorithm']['compressionSize'],"bytes):",data['compressionAlgorithm']['compression'], "(no compression)")

    print("ID",data['saltData']['saltFlag'],"Master salt/seed (size",data['saltData']['saltSize'],"bytes):",data['saltData']['salt'],"(hexadecimal)")

    print("ID",data['encryptionInitializationVector']['encryptionIVFlag'],"Encryption IV/nonce (size",data['encryptionInitializationVector']['encryptionIVSize'],"bytes):",data['encryptionInitializationVector']['encryptionIV'],"(hexadecimal)")

    print("ID",data['kdfParameters']['kdfParamFlag'],"KDF parameters (size",data['kdfParameters']['kdfParamSize'],"bytes) - Variant dictionary:")

    print("Format version:",vmdata['varientDictionaryFormat'])

    print("KDF algorithm:\n entry name ->",vmdata['uuidKDFName'],"\n size ->",vmdata['uuidKDFValueSize'],"\n value ->",vmdata['uuidKDFValue'])

    if vmdata['kdf'] == 1:
        print("This means the used KDF ALgorithm used was Argon2")
        print("Argon2 Iterations:\n entry name ->",vmdata['argon2IterationName'],"\n size ->",vmdata['argon2IterationValueSize'],"\n value ->",vmdata['argon2IterationValue'])
        print("Argon2 Memory:\n entry name ->",vmdata['argon2MemoryName'],"\n size ->",vmdata['argon2MemoryValueSize'],"\n value ->",bytes_to_mib(vmdata['argon2MemoryValue']),"MiB")
        print("Argon2 Parallelism:\n entry name ->",vmdata['argon2ParallelismName'],"\n size ->",vmdata['argon2ParallelismValueSize'],"\n value ->",vmdata['argon2ParallelismValue'],"threads")
        print("Argon2 Salt:\n entry name ->",vmdata['argon2SaltName'],"\n size ->",vmdata['argon2SaltValueSize'],"\n value ->",vmdata['argon2SaltValue'],"(hexadecimal)")
        print("Argon2 Version:\n entry name ->",vmdata['argon2VersionName'],"\n size ->",vmdata['argon2VersionValueSize'],"\n value ->",vmdata['argon2VersionValue'],"(hexadecimal)")
    else:
        print("This means the used KDF ALgorithm used was AES-KDF")
        print("AES-KDF Rounds:\n entry name ->",vmdata['aesRoundsName'],"\n size ->",vmdata['aesRoundsValueSize'],"\n value ->",vmdata['aesRoundsValue'])
        print("AES-KDF Salt/Seed:\n entry name ->",vmdata['aesSaltName'],"\n size ->",vmdata['aesSaltValueSize'],"\n value ->",vmdata['aesSaltValue'])

    if vmdata['checkEnd'] =="00":
        print("Reached the end of the Varient dictionary, continuing to read the headers of the file...")
    else:
        print("Something went wrong")
    print("ID",data['headerEndFlag'],"End of headers reached! (size",data['headerEndSize'],"bytes):",data['headerEnd'])

if __name__ == "__main__":
    main()
