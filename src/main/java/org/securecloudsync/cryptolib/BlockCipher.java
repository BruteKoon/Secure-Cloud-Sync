package org.securecloudsync.cryptolib;


import com.sun.istack.internal.NotNull;

import java.io.*;
import java.util.Arrays;

import static org.securecloudsync.filesystem.CleanPath.cleanString;
import static org.securecloudsync.ui.controllers.PopupController.wrongPopup;

/**
 * 블록단위 부분 암호화 수행하는 클레스
 */
public class BlockCipher {
    private final static int BLOCKSIZE = 67108864 * 2;
    private final static int firstBlocksize = BLOCKSIZE / 16;
    private final static int secondBlocksize = BLOCKSIZE / 8;
    private final static int[] firstSuffle = {14, 7, 9, 4, 3, 11, 15, 0, 2, 6, 1, 13, 5, 12, 8, 10};
    private final static int[] secondSuffle = {2, 7, 4, 1, 5, 0, 3, 6};

    private static final byte[] choic = {0x00};


    public static void encrypt(String file, String localPath, String securePath, String MasterPath) throws Exception {
        String psrc = localPath + "\\" + file;
        String pdes = securePath + "\\" + file + ".SCS";
        String src = cleanString(psrc);
        String des = cleanString(pdes);

        if (src == "false" || des == "false") {
            wrongPopup("wrong file Path");
        } else {
            InputStream in = new FileInputStream(src);
            OutputStream out = new FileOutputStream(des);

            byte[] dataBlock = new byte[BLOCKSIZE];
            byte[] finalBlock = new byte[BLOCKSIZE];
            byte[] frontBlock = new byte[BLOCKSIZE / 2];
            byte[] plainBlock = new byte[BLOCKSIZE / 2];
            byte[] encryptedBlock;

            byte[] iv = KeyManagement.geniv();
            byte[] key = KeyManagement.genKey();

            Crypto.encrypt(key, iv, out, MasterPath);

            while (true) {
                int read = in.read(dataBlock);
                if (read < BLOCKSIZE) {
                    byte[] finalData = new byte[read];
                    System.arraycopy(dataBlock, 0, finalData, 0, read);
                    encryptFinalBlock(finalData, out, key, iv);

                    break;
                }

                for (int i = 0; i < 16; i++) {
                    if (i > 7)
                        System.arraycopy(dataBlock, firstSuffle[i] * firstBlocksize, plainBlock, (i - 8) * firstBlocksize, firstBlocksize);
                    else
                        System.arraycopy(dataBlock, firstSuffle[i] * firstBlocksize, frontBlock, i * firstBlocksize, firstBlocksize);
                }

                encryptedBlock = Crypto.encrypt(frontBlock, key, iv);

                for (int i = 0; i < 8; i++) {
                    if (secondSuffle[i] > 3)
                        System.arraycopy(plainBlock, (secondSuffle[i] - 4) * secondBlocksize, finalBlock, i * secondBlocksize, secondBlocksize);
                    else
                        System.arraycopy(encryptedBlock, secondSuffle[i] * secondBlocksize, finalBlock, i * secondBlocksize, secondBlocksize);
                }
                out.write(finalBlock, 0, BLOCKSIZE);
                Arrays.fill(dataBlock, (byte) 0);
            }
            in.close();
            out.close();
        }
    }

    public static void decrypt( String file, String securePath, String localPath, String MasterPath) throws Exception {
        String psrc = securePath + "\\" + file;
        String pdes = localPath + "\\" + file.replace(".SCS", "");

        String src = cleanString(psrc);
        String des = cleanString(pdes);

        if (src == "false" || des == "false") {
            wrongPopup("wrong file Path");
        } else {
            InputStream in = new FileInputStream(src);
            OutputStream out = new FileOutputStream(des);
            byte[] dataBlock = new byte[BLOCKSIZE];
            byte[] finalBlock = new byte[BLOCKSIZE];
            byte[] frontBlock = new byte[BLOCKSIZE / 2];
            byte[] plainBlock = new byte[BLOCKSIZE / 2];
            byte[] decryptedBlock;

            byte[] iv = new byte[16];
            byte[] key = new byte[32];

            byte[] keyAndIv = Crypto.decrypt(in, MasterPath);

            System.arraycopy(keyAndIv, 0, key, 0, 32);
            System.arraycopy(keyAndIv, 32, iv, 0, 16);

            while (true) {
                int read = in.read(dataBlock);
                if (read < BLOCKSIZE) {

                    byte[] finalData = new byte[read];
                    System.arraycopy(dataBlock, 0, finalData, 0, read);
                    decryptFinalBlock(finalData, out, key, iv);
                    in.close();
                    break;
                }

                for (int i = 0; i < 8; i++) {
                    if (secondSuffle[i] > 3)
                        System.arraycopy(dataBlock, i * secondBlocksize, plainBlock, (secondSuffle[i] - 4) * secondBlocksize, secondBlocksize);
                    else
                        System.arraycopy(dataBlock, i * secondBlocksize, frontBlock, secondSuffle[i] * secondBlocksize, secondBlocksize);
                }

                decryptedBlock = Crypto.decrypt(frontBlock, key, iv);

                for (int i = 0; i < 16; i++) {
                    if (i > 7)
                        System.arraycopy(plainBlock, (i - 8) * firstBlocksize, finalBlock, firstSuffle[i] * firstBlocksize, firstBlocksize);
                    else
                        System.arraycopy(decryptedBlock, i * firstBlocksize, finalBlock, firstSuffle[i] * firstBlocksize, firstBlocksize);
                }

                out.write(finalBlock, 0, BLOCKSIZE);
                Arrays.fill(dataBlock, (byte) 0);
            }

            out.close();
        }
    }

    /**
     * 마지막 블록 암호화
     *
     * @param finaldata 마지막 블록
     * @param out       암호화 파일
     * @param fileKey   파일 키
     * @param fileIv    파일 iv
     * @throws IOException
     */
    private static void encryptFinalBlock(byte[] finaldata, OutputStream out, byte[] fileKey, byte[] fileIv) throws IOException {
        byte[] encryptedFinalBlock = new byte[finaldata.length];
        try {
            encryptedFinalBlock = Crypto.encrypt(finaldata, fileKey, fileIv);
        } catch (Exception e) {
            e.printStackTrace();
        }
        out.write(encryptedFinalBlock, 0, encryptedFinalBlock.length);
    }

    /**
     * @param finaldata 파일의 마지막 블록
     * @param out       복호화한 파일의 이름
     * @param key       파일 키
     * @param iv        파일 iv
     * @throws IOException
     */
    private static void decryptFinalBlock(@NotNull byte[] finaldata, OutputStream out, byte[] key, byte[] iv) throws IOException {
        byte[] decryptedFinalBlock = new byte[finaldata.length];
        try {
            decryptedFinalBlock = Crypto.decrypt(finaldata, key, iv);
        } catch (Exception e) {
            e.printStackTrace();
        }
        out.write(decryptedFinalBlock, 0, decryptedFinalBlock.length);
    }
}
