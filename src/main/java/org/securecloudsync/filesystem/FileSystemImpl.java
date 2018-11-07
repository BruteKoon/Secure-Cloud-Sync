package org.securecloudsync.filesystem;

/**
 * 파일의 경로 및 특정 마스터키파일의 이름 지정
 */
public class FileSystemImpl {
    public final static String UserPath = System.getProperty("user.home");
    public final static String plainFolderPath = UserPath + "\\Documents\\CloudSync";
    public final static String masterKeyFileName = "SCS";
}
