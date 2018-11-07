package org.securecloudsync.cryptolib;

import com.sun.istack.internal.NotNull;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * 기본 암,복호화 메소드가 있는 클레스
 */
public class Crypto {
    public static byte[] encrypt(byte[] plainText, byte[] key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        // Encrypt.
        Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(plainText);

        return encrypted;
    }

    public static byte[] decrypt(byte[] encryptedBytes, byte[] key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        // Decrypt.
        Cipher cipherDecrypt = Cipher.getInstance("AES/CTR/PKCS5Padding");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decrypted = cipherDecrypt.doFinal(encryptedBytes);

        return decrypted;
    }

    //MasterPath = 마스터키 경로
    static void encrypt(byte[] key, byte[] iv, @NotNull OutputStream out, String MasterPath) throws Exception {
        byte[] masterKey = KeyManagement.genMasterKey (MasterPath);
        byte[] masterIv = KeyManagement.geniv();

        byte[] keyAndIV = new byte[48];
        System.arraycopy(key, 0, keyAndIV, 0, 32);
        System.arraycopy(iv, 0, keyAndIV, 32, 16);
        out.write(masterIv);
        out.write(Crypto.encrypt(keyAndIV, masterKey, masterIv));
    }

    //MasterPath = 마스터키 경로
    static byte[] decrypt(@NotNull InputStream in, String MasterPath) throws Exception {
        byte[] keyAndIv = new byte[48];
        byte[] masterIv = new byte[16];
        byte[] masterKey = KeyManagement.genMasterKey (MasterPath);

        in.read(masterIv);
        in.read(keyAndIv);
        byte[] k = Crypto.decrypt(keyAndIv, masterKey, masterIv);
        return k;
    }


}
