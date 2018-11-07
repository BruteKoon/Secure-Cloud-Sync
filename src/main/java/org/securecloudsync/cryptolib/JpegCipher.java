package org.securecloudsync.cryptolib;

import com.sun.istack.internal.NotNull;

import java.io.*;
import java.util.Arrays;

import static org.securecloudsync.filesystem.CleanPath.cleanString;
import static org.securecloudsync.ui.controllers.PopupController.wrongPopup;

/**
 * jpeg파일 부분 암호화를 수행하는 클레스
 */
public class JpegCipher {

    private final static byte[] tableFlag = {(byte) 0xff, (byte) 0xdb};

    /**
     * @param file       암호화 할 파일 이름
     * @param MasterPath 마스터키 경로
     * @throws Exception
     */
    public static void encrypt(String file, String localPath, String securePath, String MasterPath) throws Exception {
        String psrc = localPath + "\\" + file;
        String pdes = securePath + "\\" + file + ".SCS";
        String src = cleanString(psrc);
        String des = cleanString(pdes);

        if (src == "false" || des == "false") {
            wrongPopup("wrong file Path");
        } else {
            File efile = new File(src);
            int size = (int) efile.length();
            byte[] iv = KeyManagement.geniv();
            byte[] key = KeyManagement.genKey();

            InputStream in = new FileInputStream(src);
            OutputStream out = new FileOutputStream(des);
            Crypto.encrypt(key, iv, out, MasterPath);

            int tablesize;
            int pointer = 20;
            byte[] flag = new byte[2];
            byte[] tableLength = new byte[2];
            byte[] data = new byte[size];
            in.read(data);
            while (true) {
                System.arraycopy(data, pointer, flag, 0, 2);
                if (Arrays.equals(flag, tableFlag)) {
                    while (true) {
                        pointer += 2;
                        System.arraycopy(data, pointer, tableLength, 0, 2);
                        tablesize = hexToDec(tableLength) - 2;

                        byte[] table = new byte[tablesize];
                        pointer += 2;
                        System.arraycopy(data, pointer, table, 0, tablesize);
                        byte[] encrypt = Crypto.encrypt(table, key, iv);
                        System.arraycopy(encrypt, 0, data, pointer, tablesize);
                        pointer += tablesize;

                        System.arraycopy(data, pointer, flag, 0, 2);
                        if (Arrays.equals(flag, tableFlag)) {
                        } else {
                            break;
                        }
                    }
                    break;
                }
                pointer += 2;
                System.arraycopy(data, pointer, tableLength, 0, 2);
                tablesize = hexToDec(tableLength);
                pointer += tablesize;
            }

            out.write(data);
            in.close();
            out.close();
        }
    }


    /**
     * @param file       복호화 할 파일 이름
     * @param MasterPath 마스터키 경로
     * @throws Exception
     */
    public static void decrypt(@NotNull String file, String securePath, String localPath, String MasterPath) throws Exception {
        String psrc = securePath + "\\" + file;
        String pdes = localPath + "\\" + file.replace(".SCS", "");

        String src = cleanString(psrc);
        String des = cleanString(pdes);

        if (src == "false" || des == "false") {
            wrongPopup("wrong file Path");
        } else {

            byte[] iv = new byte[16];
            byte[] key = new byte[32];

            InputStream in = new FileInputStream(src);
            OutputStream out = new FileOutputStream(des);

            byte[] keyAndIv = Crypto.decrypt(in, MasterPath);

            System.arraycopy(keyAndIv, 0, key, 0, 32);
            System.arraycopy(keyAndIv, 32, iv, 0, 16);

            File efile = new File(src);
            int size = (int) efile.length();
            byte[] flag = new byte[2];
            byte[] tableLength = new byte[2];
            byte[] data = new byte[size - keyAndIv.length];
            int tablesize = 0;
            int pointer = 20;

            in.read(data);

            while (true) {
                System.arraycopy(data, pointer, flag, 0, 2);
                if (Arrays.equals(flag, tableFlag)) {
                    while (true) {
                        pointer += 2;
                        System.arraycopy(data, pointer, tableLength, 0, 2);
                        tablesize = hexToDec(tableLength) - 2;

                        byte[] table = new byte[tablesize];
                        pointer += 2;
                        System.arraycopy(data, pointer, table, 0, tablesize);

                        byte[] decrypt = Crypto.decrypt(table, key, iv);
                        System.arraycopy(decrypt, 0, data, pointer, tablesize);
                        pointer += tablesize;

                        System.arraycopy(data, pointer, flag, 0, 2);
                        if (Arrays.equals(flag, tableFlag)) {
                        } else {
                            break;
                        }
                    }
                    break;
                }
                pointer += 2;
                System.arraycopy(data, pointer, tableLength, 0, 2);
                tablesize = hexToDec(tableLength);
                pointer += tablesize;
            }
            out.write(data);
            in.close();
            out.close();
        }
    }


    /**
     * @param tableLength 양자 테이블 길이(Byte)
     * @return 양자 테이블 길이(int)
     */
    private static int hexToDec(@NotNull byte[] tableLength) {
        int length = tableLength[1] & 0x1;
        for (int i = 1; i < 8; i++) {
            int temp = (int) (((tableLength[1] >> i) & 0x1) * Math.pow(2, i));
            length += temp;
        }
        for (int i = 0; i < 8; i++) {
            int temp = (int) (((tableLength[0] >> i) & 0x1) * Math.pow(2, i + 8));
            length += temp;
        }
        return length;
    }
}
