package org.securecloudsync.cryptolib;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.util.Arrays;

import static java.lang.Thread.sleep;
import static org.securecloudsync.filesystem.CleanPath.cleanString;
import static org.securecloudsync.ui.controllers.PopupController.wrongPopup;

/**
 * 파일의 확장자를 확인하여 확장자별 클레스로 보내 암,복호화를 수행하는 클레스
 */
public class CipherMain {

    public static void decrypt(String file, String Path, String des, String Master_Path) throws Exception {
        String psrc = Path + "\\" + file;
        String src = cleanString(psrc);
        if (src == "false") {
            wrongPopup("wrong file Path");
        } else {
            RandomAccessFile in = new RandomAccessFile(src, "r");

            in.seek(64);
            byte[] flag = new byte[4];
            byte[] jpg = {(byte) 0xff, (byte) 0xd8, (byte) 0xff, (byte) 0xe0};
            byte[] mp4 = {(byte) 0x66, (byte) 0x74, (byte) 0x79, (byte) 0x70};
            in.read(flag, 0, 4);
            if (Arrays.equals(flag, jpg)) {
                JpegCipher.decrypt(file, Path, des, Master_Path);
            } else {
                in.read(flag);
                in.close();
                if (Arrays.equals(flag, mp4)) {
                    Mp4Cipher.decrypt(file, Path, des, Master_Path);
                } else {
                    BlockCipher.decrypt(file, Path, des, Master_Path);
                }
            }
        }
    }

    public static void encrypt(String file, String Path, String des, String Master_Path) throws Exception {
        String psrc = Path + "\\" + file;
        sleep(2000);

        String src = cleanString(psrc);
        if (src == "false") {
            wrongPopup("wrong file Path");
        } else {
            InputStream in = new FileInputStream(src);
            byte[] flag = new byte[4];
            byte[] jpg = {(byte) 0xff, (byte) 0xd8, (byte) 0xff, (byte) 0xe0};
            byte[] mp4 = {(byte) 0x66, (byte) 0x74, (byte) 0x79, (byte) 0x70};
            in.read(flag, 0, 4);

            if (Arrays.equals(flag, jpg)) {
                in.close();
                JpegCipher.encrypt(file, Path, des, Master_Path);
            } else {
                in.read(flag);
                in.close();
                if (Arrays.equals(flag, mp4)) {
                    Mp4Cipher.encrypt(file, Path, des);
                } else {
                    BlockCipher.encrypt(file, Path, des, Master_Path);
                }
            }
        }
    }
}
