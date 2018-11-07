package org.securecloudsync.cryptolib;

import com.sun.istack.internal.NotNull;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.*;
import java.lang.ref.WeakReference;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.securecloudsync.filesystem.CleanPath.checkString;
import static org.securecloudsync.filesystem.CleanPath.cleanString;
import static org.securecloudsync.filesystem.FileSystemImpl.masterKeyFileName;
import static org.securecloudsync.ui.controller.LoginController.folderPaasword;
import static org.securecloudsync.ui.controllers.PopupController.wrongPopup;

/**
 * 마스터키 파일을 관리하는 클레스
 * 마스터키 파일 생성, 복호화 등을 수행
 */
public class KeyManagement {

    private static String passwd;
    static SecureRandom random = new SecureRandom();
    final static int ITERATIONS = 1000;
    final static String ALGO = "PBEWithHmacSHA256AndAES_128";
    final static byte[] f = {0x00};

    public static byte[] genMasterKey (String MasterPath) throws Exception {
        String psrc = MasterPath + "\\" + masterKeyFileName;
        String src = cleanString(psrc);
        if (src == "false") {
            wrongPopup("wrong file Path");
            return f;
        } else {
            SecretKey pk = genPersonalKey();
            src.replace("\\n", "");
            InputStream in = new FileInputStream(src);
            return solvePersonalMK(pk, in);

        }
    }

    private static byte[] solvePersonalMK(SecretKey pk, @NotNull InputStream in) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] size = new byte[1];
        in.read(size);
        in.read(size);
        byte[] encodeSalt = new byte[hexToDec(size)];
        in.read(encodeSalt);

        in.read(size);
        byte[] encodeiv = new byte[hexToDec(size)];
        in.read(encodeiv);
        byte[] iv = Base64.decodeBase64(encodeiv);

        in.read(size);
        byte[] encodeMasterKey = new byte[hexToDec(size)];
        in.read(encodeMasterKey);

        in.read(size);
        byte[] encodesha = new byte[hexToDec(size)];
        in.read(encodesha);

        PBEParameterSpec parameterSpec = new PBEParameterSpec(Base64.decodeBase64(encodeSalt), ITERATIONS, new IvParameterSpec(iv));
        Cipher pbeCipher = Cipher.getInstance(ALGO);
        pbeCipher.init(Cipher.DECRYPT_MODE, pk, parameterSpec);
        byte[] masterKey;
        try {
            masterKey = pbeCipher.doFinal(Base64.decodeBase64(encodeMasterKey));
        }catch(Exception e) {
            in.close();
            return f;
        }
        in.close();
        if (java.util.Arrays.equals(encodesha, Base64.encodeBase64(masterKeysha(masterKey)))) {
            return masterKey;
        } else {
            return f;
        }
    }


    public static byte[] genKey() {
        byte[] key = new byte[32];
        random.nextBytes(key);

        return key;
    }


    static byte[] geniv() {
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        return iv;
    }

    static PBEParameterSpec genPersonalSalt(byte[] iv) {
        byte[] salt = new byte[8];
        random.nextBytes(salt);
        PBEParameterSpec parameterSpec = new PBEParameterSpec(salt, ITERATIONS, new IvParameterSpec(iv));
        return parameterSpec;
    }


    public static SecretKey genPersonalKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        char[] charArray = new char[folderPaasword.length];
        for(int i = 0; i < folderPaasword.length; i++){
            charArray[i] = (char)folderPaasword[i];
        }
        PBEKeySpec keySpec = new PBEKeySpec(charArray);
        for(int i = 0; i < charArray.length; i++){
            charArray[i] = 0x00;
        }
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGO);
        SecretKey key = keyFactory.generateSecret(keySpec);
        keySpec = null;
        gc();
        return key;
    }

    public static void gc() {
        Object obj = new Object();
        WeakReference ref = new WeakReference<Object>(obj);
        obj = null;
        while(ref.get() != null) {
            System.gc();
        }
    }


    public static void makeMasterkeyFile(File secureFolder, int Group) throws Exception {
        String psrc = secureFolder + "\\" + masterKeyFileName;

        String src = checkString(psrc);
        if (src == "false") {
            wrongPopup("wrong file Path");
        } else {
            OutputStream out = new FileOutputStream(src);
            byte[] isGroup = {0};
            byte[] iv = geniv();

            int size;

            PBEParameterSpec salt = genPersonalSalt(iv);
            byte[] masterKey = genKey();
            SecretKey pk = genPersonalKey();

            Cipher pbeCipher = Cipher.getInstance(ALGO);
            pbeCipher.init(Cipher.ENCRYPT_MODE, pk, salt);
            byte[] encodeSalt = Base64.encodeBase64(salt.getSalt());
            size = encodeSalt.length;
            out.write(isGroup);
            out.write(size);
            out.write(encodeSalt);

            out.write(Base64.encodeBase64(iv).length);
            out.write(Base64.encodeBase64(iv));


            byte[] encodeMasterKey = pbeCipher.doFinal(masterKey);
            size = Base64.encodeBase64(encodeMasterKey).length;
            out.write(size);
            out.write(Base64.encodeBase64(encodeMasterKey));

            byte[] encodesha = Base64.encodeBase64(masterKeysha(masterKey));
            out.write(encodesha.length);
            out.write(encodesha);

            out.close();
        }
    }
    public static void makeMasterkeyFile(String secureFolder, byte[] masterKey) throws Exception {
        String psrc = secureFolder + "\\" + masterKeyFileName;
        String src = cleanString(psrc);
        if (src == "false") {
            wrongPopup("wrong file Path");
        } else {
            OutputStream out = new FileOutputStream(src);
            byte[] isGroup = {0};
            byte[] iv = geniv();

            int size;

            PBEParameterSpec salt = genPersonalSalt(iv);
            SecretKey pk = genPersonalKey();

            Cipher pbeCipher = Cipher.getInstance(ALGO);
            pbeCipher.init(Cipher.ENCRYPT_MODE, pk, salt);
            byte[] encodeSalt = Base64.encodeBase64(salt.getSalt());
            size = encodeSalt.length;
            out.write(isGroup);
            out.write(size);
            out.write(encodeSalt);

            out.write(Base64.encodeBase64(iv).length);
            out.write(Base64.encodeBase64(iv));


            byte[] encodeMasterKey = pbeCipher.doFinal(masterKey);
            size = Base64.encodeBase64(encodeMasterKey).length;
            out.write(size);
            out.write(Base64.encodeBase64(encodeMasterKey));

            byte[] encodesha = Base64.encodeBase64(masterKeysha(masterKey));
            out.write(encodesha.length);
            out.write(encodesha);

            out.close();
        }
    }

    private static byte[] masterKeysha(byte[] encodeMasterKey) throws NoSuchAlgorithmException {
        MessageDigest mDigest = MessageDigest.getInstance("SHA-256");
        mDigest.update(encodeMasterKey);
        return mDigest.digest();
    }

    public static boolean validationPasswd(String pw) {
        Pattern p = Pattern.compile("^(?=.*?[A-Za-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-])[A-Za-z\\d$@$!%*#?&].{6,}$");
        Matcher mtch = p.matcher(pw);

        if (mtch.matches()) {
            return true;
        }
        return false;
    }

    private static int hexToDec( byte[] tableLength) {
        int length = tableLength[0] & 0x1;
        for (int i = 1; i < 8; i++) {
            int temp = (int) (((tableLength[0] >> i) & 0x1) * Math.pow(2, i));
            length += temp;
        }

        return length;
    }
}
