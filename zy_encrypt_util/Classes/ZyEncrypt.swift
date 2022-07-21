

import Foundation
import CryptoSwift

public class ZyEncrypt{
    public class func encriptar(inputdata:String , pass:String) -> String{
        //encrypt:operation: Operation, algorithm: Algorithm, mode: Mode, padding: Padding, key: String, iv
        //print ("enriptacion funcion \n \(inputdata)")
        print("🔗","=====>>> INICIO encriptar")

        let iv = AES.randomIV(128/8)
        let password: [UInt8] = Array(pass.bytes)
        let salt: [UInt8] = AES.randomIV(256/8)
        
        /* Generate a key from a `password`. Optional if you already have a key */
        let key = try! PKCS5.PBKDF2(
            password: password,
            salt: salt,
            iterations: 1989,
            keyLength: 32, /* AES-256 */
            variant: .sha1
        ).calculate()
        
        /* Generate random IV value. IV is public value. Either need to generate, or get it from elsewhere */
        
        /* AES cryptor instance */
        let aes = try! AES(key: key, blockMode: CBC(iv: iv), padding: .pkcs7)
        
        /* Encrypt Data */
        let encryptedBytes = try! aes.encrypt(inputdata.bytes)
        let encryptedData = Data(encryptedBytes)
        
        let cipherTextData = encryptedData
        
        //print ("cipherTextData: \n \(cipherTextData)")
        
        let totalcifer = salt.toHexString() + iv.toHexString()  + cipherTextData.base64EncodedString()
        
        //print ("totalcifer: \n \(totalcifer)")
        
        let finalreturn = totalcifer.toBase64()
        
        //print ("encrypted final: \n \(finalreturn)")
        print("🔗","=====>>> FIN encriptar")
        return finalreturn
    }

    public class func desencriptar(inputdata:String, pass:String) -> String{
        //encrypt:operation: Operation, algorithm: Algorithm, mode: Mode, padding: Padding, key: String, iv
        //print ("desenriptacion funcion \n \(inputdata)")

        //let kwy = keydecode(oauthToken: LoginSetting.token)
        print("🔗","=====>>> Inicio Desencriptar")
        let password: [UInt8] = Array(pass.bytes)
            
        let decodeBase64Code = Data(base64Encoded: inputdata + repeatElement("=", count: inputdata.count.isMultiple(of: 4) ? 0 : 4 - inputdata.count % 4), options: Data.Base64DecodingOptions.ignoreUnknownCharacters)!
        
        let decodedString = String(data: decodeBase64Code, encoding: .utf8)!
        
        
        let totalcifer: [UInt8]  = Array(decodedString.bytes)
        
        let salt =  String(bytes: copyOfRange(arr: totalcifer, from: 0, to: (256/4))!, encoding: .utf8)
        let iv  = String(bytes: copyOfRange(arr: totalcifer, from: (256/4), to: ((256+128)/4))!
                         , encoding: .utf8)
        let encryptedBase  =  copyOfRange(arr: totalcifer, from: ((256+128)/4), to: totalcifer.count)!
       
        let decocodeBase = (String(bytes: encryptedBase, encoding: .utf8))!
        
        
        let decodeBase64Codesecond = Data(base64Encoded: decocodeBase + repeatElement("=", count: decocodeBase.count.isMultiple(of: 4) ? 0 : 4 - decocodeBase.count % 4) , options: Data.Base64DecodingOptions.ignoreUnknownCharacters)!
        
        let key = try! PKCS5.PBKDF2(
            password: password,
            salt: Array<UInt8>(hex: salt!),
            iterations: 1989,
            keyLength: 32, /* AES-256 */
            variant: .sha1
        ).calculate()
        
        /* AES cryptor instance */
        let aes = try! AES(key: key, blockMode: CBC(iv: Array<UInt8>(hex: iv!) ), padding: .pkcs5)
        
        /* Decrypt Data */
        let decryptedBytes = try! aes.decrypt(Array(decodeBase64Codesecond.bytes))
        
        let decryptedData = Data(decryptedBytes)
        
        let finalDecode = (String(bytes: decryptedData, encoding: .utf8))!
        print("🔗","=====>>> Fin Desencriptar")
        return finalDecode
        
    }

    private class func copyOfRange<T>(arr: [T], from: Int, to: Int) -> [T]? where T: ExpressibleByIntegerLiteral {
        guard from >= 0 && from <= arr.count && from <= to else { return nil }
        
        var to = to
        var padding = 0
        
        if to > arr.count {
            padding = to - arr.count
            to = arr.count
        }
        
        return Array(arr[from..<to]) + [T](repeating: 0, count: padding)
    }
    
    

}

extension String {
    func index(from: Int) -> Index {
        return self.index(startIndex, offsetBy: from)
    }
    
    func substring(from: Int) -> String {
        let fromIndex = index(from: from)
        return String(self[fromIndex...])
    }
    
    func substring(to: Int) -> String {
        let toIndex = index(from: to)
        return String(self[..<toIndex])
    }
    
    func substring(with r: Range<Int>) -> String {
        let startIndex = index(from: r.lowerBound)
        let endIndex = index(from: r.upperBound)
        return String(self[startIndex..<endIndex])
    }
    
    
    
    func toBase64() -> String {
        return Data(self.utf8).base64EncodedString()
    }
    
}
