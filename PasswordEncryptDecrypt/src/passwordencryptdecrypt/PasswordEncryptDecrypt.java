/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package passwordencryptdecrypt;

/**
 *
 * @author onurd
 */
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
//SecretKeySpecThe easiest way to  do this is to construct a new SecretKeySpec object, using the original key data and explicitly specifying the algorithm name: 
import javax.crypto.spec.SecretKeySpec;

public class PasswordEncryptDecrypt {
    // Secret Key 16 karakterden oluşması şarttır
    private static final String SECRET_KEY = "SecretKeyExemple";

    // Scannerdan dolayı throw Execption metodunu kullandık
    public static String encrypt(String password) throws Exception {
        //SecretKeySpec gizli anahtarın Temsilini sağlar
        //getBytes() metodu ile SECRET_KEY Stringini Byte dizisine dönüştürür böylece SecretKeySpec AES ile şifreleme yapabilir
        //SECRET_KEY değişkenini AES algoritması kullnaratak yeni bir SecretKeySpec nesnesi oluşturur
        SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        //Bir Cipher İnstance oluşurtur böylece belirlediğimiz algoritmayı uygular
        Cipher cipher = Cipher.getInstance("AES");
        // Cipher init metodu ile şifreleme veya şifre çözmek için şifreyi başlatır
        //init metodunu ilk argümanında şifreleme mi yoksa deşifreleme mi yapılcağı yazılır ikincideyse SecretKey yazılır
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        //Burda şifreleme işlemi yapılır sonrada encpyedPassword byte dizisi şeklinde tutulur
        byte[] encryptedPassword = cipher.doFinal(password.getBytes());
        // Şifrelenmmiş passwordu base64 biçiminde kodlar sonrada Stringe dönüştürüp geridöndürü(return eder)
        return Base64.getEncoder().encodeToString(encryptedPassword);
    }

    // Şifrelenmiş metni deşifreleme
    public static String decrypt(String encryptedPassword) throws Exception {
        // SecretKey oluşturulur
        SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        // Deşifreleme için Cipher Instance oluşturulur
        Cipher cipher = Cipher.getInstance("AES");
        // Deşifreleme işlemini başlatır
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        // encrytedPassword adıyla taşınan şifrelenmiş byte dizinin Base64 kodlamasından çözüp saf byte dizini saf bayt dizisine dönüştürür
        // ayrıca decryptedPassword byte dizinde tutulur
        byte[] decryptedPassword = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
        // 
        return new String(decryptedPassword);
    }

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Would you like to (E)ncrypt or (D)ecrypt a password?"+"\n"+"Note:For Encryption write E for Decryption write D");
        
        String input = scanner.nextLine();
        //equalsIgnoreCase te eğer eğer yazılan ile istenilen Sring aynıysa true değilse false şeklinde geri döner
        if (input.equalsIgnoreCase("E")) {
            // Şifreleme
            System.out.println("Enter the password to encrypt:");
            String password = scanner.nextLine();
            String encryptedPassword = encrypt(password);
            System.out.println("Encrypted password: " + encryptedPassword);
        } 
        else if (input.equalsIgnoreCase("D")) {
            // Deşifreleme
            System.out.println("Enter the encrypted password to decrypt:");
            String encryptedPassword = scanner.nextLine();
            String decryptedPassword = decrypt(encryptedPassword);
            System.out.println("Decrypted password: " + decryptedPassword);
        } 
        else {
            System.out.println("Invalid input. Please try again.");
        }

     }
}