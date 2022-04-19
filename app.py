


from flask import Flask, redirect,render_template,request,flash,jsonify
import os
from PIL import Image
import stepic
from Crypto.Cipher import AES
import base64
from cryptography.fernet import Fernet
import hashlib



app = Flask(__name__)

APP_ROOT= os.path.dirname(os.path.abspath(__file__))

## HOME PAGE
@app.route('/')
def home():
     return render_template("home.html")




##Steganography
@app.route("/steg")
def steg():
    return render_template('steg.html')


### (ENCODING)
@app.route("/upload", methods=['POST'])
def upload():
    target =os.path.join(APP_ROOT,'images/')
    if not os.path.isdir(target):
        os.mkdir(target)

    for file in request.files.getlist('file'):
        filename=file.filename
        destination="/".join([target,filename])
        file.save(destination)
    
    if request.method=='POST':
        data=request.form["text"]
        im=Image.open (destination)

        im2=stepic.encode(im,bytes(data,encoding='utf-8'))
        for file in request.files.getlist('file'):
         filename=file.filename 
         dest="/".join([target,filename])
         im2.save(dest)
    return 'SUCCESS'

###(DECODING)
@app.route('/dec')
def dec():
    return render_template('decode.html')
@app.route('/decode', methods=['GET','POST'])
def decode():
    '''
    target =os.path.join(APP_ROOT,'images/')
    if not os.path.isdir(target):
        os.mkdir(target)

    for file in request.files.getlist('file'):
        filename=file.filename
        destination="/".join([target,filename])
        file.save(destination)
        '''
    if request.method=='POST':
        
         img=request.files["file"]
         im= Image.open(img)
        
         s=stepic.decode(im) 
         msg= "Message : "+s

    return msg

## Encryption and Decryption
@app.route("/encrypt")
def encrypt():
    return render_template('encrypt.html')

@app.route("/enc", methods=['POST'])
def enc():
    if request.method=='POST':
        data=request.form["enctext"]
        res=base64.b64encode(bytes(data,encoding='utf-8'))
        print(res)
        return res

@app.route('/decrypt')
def decrypt():
    return render_template('decryption.html')
@app.route("/decry",methods=['POST'])
def decry():
    if request.method=='POST':
        cipher=request.form["decryptext"]
        res=base64.b64decode(cipher)
        print(res)
        return res


### FILE ENCRYPTION
@app.route('/fenc')
def fenc():
    return render_template('fileenc.html')

@app.route('/fileenc',methods=['POST'])
def fileenc():
    key = Fernet.generate_key()
  
# string the key in a file
    with open('filekey.key', 'wb') as filekey:
         filekey.write(key)
        
    with open('filekey.key', 'rb') as filekey:
         key = filekey.read()
  
# using the generated key
    fernet = Fernet(key)
  
# opening the original file to encrypt
    if request.method=='POST':
        filess=request.files["file"]
        filename=filess.filename
        with open(filename, 'rb') as file:
            original = file.read()
      
# encrypting the file
    encrypted = fernet.encrypt(original)
  
# opening the file in write mode and 
# writing the encrypted data
    with open(filename, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

    return "File Data is Successfully Encrypted" 

@app.route('/filedec')
def filedec():
    return render_template("filedecrypt.html") 

@app.route('/filedecrypt',methods=['POST'])
def filedecrypt():

     with open('filekey.key', 'rb') as filekey:
         key = filekey.read()
     fernet = Fernet(key)
  
# opening the encrypted file
     if request.method=='POST':
        filess=request.files["file"]
        filename=filess.filename
        with open(filename, 'rb') as enc_file:
         encrypted = enc_file.read()
  
# decrypting the file
     decrypted = fernet.decrypt(encrypted)
  
# opening the file in write mode and
# writing the decrypted data
     with open(filename, 'wb') as dec_file:
         dec_file.write(decrypted)
    
     return "File Data Decrypted Successfully!!!"

#hashing
@app.route('/hash')  
def hash():
    return render_template("hash.html")

@app.route('/md5')
def md5():
    return render_template('md5.html')
@app.route('/md',methods=['POST'])
def md():
     if request.method=='POST':
        filess=request.files["file"]
        filename=filess.filename
        with open(filename, 'rb') as f:
         buff=f.read()
         hash=hashlib.md5(buff).hexdigest()
     return hash  
@app.route('/sha256')
def sha256():
    return render_template('sha256.html')
@app.route('/shaa',methods=['POST'])
def shaa():
        if request.method=='POST':
         filess=request.files["file"]
         filename=filess.filename
        with open(filename, 'rb') as f:
         buff=f.read()
         hash=hashlib.sha256(buff).hexdigest()
        return hash

@app.route('/sha512')
def sha512():
    return render_template('sha512.html')
@app.route('/shaaa',methods=['POST'])
def shaaa():
        if request.method=='POST':
         filess=request.files["file"]
         filename=filess.filename
        with open(filename, 'rb') as f:
         buff=f.read()
         hash=hashlib.sha512(buff).hexdigest()
        return hash     
'''
@app.route("/integrity")
def integrity():
    return render_template("integritycalc.html")
@app.route("/integritycheck",methods=['POST'])
def integritycheck():
    if request.method=='POST':
        for f in request.files.getlist('filename'):
         
         filename=f.filename
         with open(filename, 'rb') as g:
          buff=g.read()
          hash=hashlib.sha512(buff).hexdigest()
          print(hash)
'''        
#Image encryption
@app.route('/imageenc') 
def imageenc():
    return render_template('imageenc.html')      

@app.route('/imenc',methods=['POST'])
def imenc():
    target =os.path.join(APP_ROOT,'imagesenc/')
    if not os.path.isdir(target):
        os.mkdir(target)

    for file in request.files.getlist('file'):
        filename=file.filename
        destination="/".join([target,filename])
        file.save(destination)
    if request.method=='POST':
        

       
        
          key=request.form["imgtext"]
          f=open(destination,'rb')
          image=f.read()
          f.close()
          image=bytearray(image)
          for index,values in enumerate(image):
             image[index]=values^int(key)
          f1=open("encrypted.jpg",'wb')
         
          f1.write(image)
          f1.close()
    return "Image Encrypted succesfully!!!"

@app.route('/imagedec')
def imagedec():
    return render_template("imagedec.html")

@app.route('/imdec',methods=['POST'])
def imdec():
     if request.method=='POST':
          key=request.form["imgtext"]
          f=open("encrypted.jpg",'rb')
          image=f.read()
          f.close()
          image=bytearray(image)
          for index,values in enumerate(image):
             image[index]=values^int(key)
          f1=open("decrypted.jpg",'wb')
         
          f1.write(image)
          f1.close()
     return "Image Decrypted Successfully!!!"






    
if __name__=="__main__":
    app.run(debug=True)