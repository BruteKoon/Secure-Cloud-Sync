package org.securecloudsync.ui.controller;



import com.sun.istack.internal.NotNull;

import java.io.File;
import java.io.FileWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.securecloudsync.filesystem.CleanPath.cleanString;
import static org.securecloudsync.filesystem.FileSystemImpl.plainFolderPath;
import static org.securecloudsync.ui.controller.LoginController.fileListName;
import static org.securecloudsync.ui.controllers.PopupController.wrongPopup;

/**
 * 파일 리스트를 저장, 관리하는 클레스
 */
public class FileListManagement {
    /**
     * 파일 리스트를 파일 형태로 보관하여 저장
     *
     * @param selectedFile 리스트에서 선택한 폴더
     */
    public static void fileListWrite(@NotNull File selectedFile) {
        String fileName = selectedFile.getName();
        String filePath = selectedFile.getPath();

        try {
            String psrc = plainFolderPath + "\\" + fileListName;
            String src = cleanString(psrc);
            if (src == "false") {
                wrongPopup("wrong file Path");
            } else {
                File file = new File(src);
                FileWriter fw = new FileWriter(file, true);

                fw.write(filePath + "\t" + fileName + "\n");
                fw.flush();
                fw.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @NotNull
    public static String fileNamesha(@NotNull String gkPath) throws NoSuchAlgorithmException {
        MessageDigest mDigest = MessageDigest.getInstance("SHA-256");
        mDigest.update(gkPath.getBytes());
        byte[] gkNameSha = mDigest.digest();
        byte[] gkName = new byte[8];
        System.arraycopy(gkNameSha, 0, gkName, 0, gkName.length);
        return byteArrayToHex(gkName);
    }

    @NotNull
    public static String byteArrayToHex(@NotNull byte[] a) {
        StringBuilder sb = new StringBuilder();
        for(final byte b: a)
            sb.append(String.format("%02x", b&0xff));
        return sb.toString();
    }
}
