package org.securecloudsync.filesystem;

import com.sun.istack.internal.NotNull;
import org.securecloudsync.cryptolib.CipherMain;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashMap;
import java.util.Map;

import static java.nio.file.StandardWatchEventKinds.*;
import static org.securecloudsync.cryptolib.CipherMain.decrypt;

/**
 * 마운트한 보관함의 파일을 감지하여, 암호 및 복호화를 수행
 */
public class DetectThread extends Thread {
    //감지시스템의 default 변수
    public WatchKey watchKey;
    public WatchService watchService;
    public WatchService watcher;
    public Map<WatchKey, java.nio.file.Path> keys;
    public java.nio.file.Path sharedDirectoryPath;

    //폴더의 경로를 갖고 오기 위한 변수(마운트 했을 때)
    String Path;
    String securePath;
    String Master_Path;

    String Default_Path;
    String Default_securePath;

    Path dir;

    int Create_Flag;

    //마운트 할 때 사용
    public DetectThread(String path, String securepath) throws IOException {
        Path = path;
        securePath = securepath;
        Master_Path = securepath;

        Default_Path = path;
        Default_securePath = securepath;
        Create_Flag = 0;

        this.watcher = FileSystems.getDefault().newWatchService();
        this.keys = new HashMap<WatchKey, Path>();
        walkAndRegisterDirectories(Paths.get(path));
    }

    //재귀 탐색
    public void Recursion(File file, WatchEvent<?> WEvent) throws InterruptedException {
        WatchEvent.Kind<?> event = WEvent.kind();
        //Create 일때만 기능 작동
        if (event == ENTRY_CREATE) {
            Create_Flag = 1;
            //기본 폴더에 대응되는 시큐어폴더의 경로 설정
            if (file.getParent().equals(Default_Path)) {
                securePath = Default_securePath;

            } else {
                String tt = file.getParent();
                securePath = Default_securePath + tt.replace(Default_Path, "");
            }

            if (file.exists()) {
                //해당 파일이 폴더일 경우
                if (file.isDirectory()) {

                    //시큐어 폴더쪽에 대응되는 폴더 생성
                    File mkdir_tmp = new File(securePath + "\\" + file.getName());
                    mkdir_tmp.mkdirs();

                    //리스트에 제대로 파일들을 받기 위해 sleep 으로 시간의 텀을 줌
                    try {
                        sleep(1000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                    //폴더 안 파일들을 리스트 형태로 저장
                    File[] list_file = file.listFiles();

                    //리스트 형태로 저장한 파일들을 recursion
                    for (int i = 0; i < list_file.length; i++) {

                        //securePath = securePath + file.getName()
                        Recursion(list_file[i], WEvent);
                        Path = Default_Path;
                        securePath = Default_securePath;
                        //가장 중요!, 폴더안에 파일이 여러개인데, 처음에 1개만 인식! 그렇기에, 반복문끝에 파일을 다시 받아 제대로된 폴더 안 파일 및 갯수 파악
                        list_file = file.listFiles();
                    }

                }
                //해당 파일이 파일일 경우
                if (file.isFile()) {
                    sleep(2000);
                    if (!file.getName().contains(".tmp")) {
                        if (!file.getName().contains("~$")) {

                            try {

//                        if (FR_num > 0) {
                                //암호화 실행
                                CipherMain.encrypt(file.getName(), file.getParent(), securePath, Master_Path);
//                        }
                            } catch (FileNotFoundException e) {
                                e.printStackTrace();
                            } catch (IOException e) {
                                e.printStackTrace();
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    }
                }
            }
            Create_Flag = 0;
        }
        if (event == ENTRY_MODIFY && Create_Flag == 0) {
            //기본 폴더에 대응되는 시큐어폴더의 경로 설정
            if (file.getParent().equals(Default_Path)) {
                securePath = Default_securePath;
            } else {
                String tt = file.getParent();
                securePath = Default_securePath + tt.replace(Default_Path, "");
            }

            if (file.exists()) {
                //해당 파일이 파일일 경우
                if (file.isFile()) {
                    try {
                        CipherMain.encrypt(file.getName(), file.getParent(), securePath, Master_Path);
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                }
            }
        }
    }

    private void walkAndRegisterDirectories(final Path start) throws IOException {
        Files.walkFileTree(start, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                registerDirectory(dir);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private void registerDirectory(@NotNull Path dir) throws IOException {
        WatchKey key = dir.register(watcher, ENTRY_CREATE, ENTRY_DELETE, ENTRY_MODIFY);
        keys.put(key, dir);
    }

    public void run() {
        WatchKey key;
        //무한 반복(계속적으로 탐지하기를 위함)
        for (; ; ) {
            try {
                key = watcher.take();
            } catch (InterruptedException x) {
                return;
            }
            dir = keys.get(key);
            if (dir == null) {
                continue;
            }

            for (WatchEvent<?> event : key.pollEvents()) {
                WatchEvent.Kind kind = event.kind();
                Path name = ((WatchEvent<Path>) event).context();
                Path child = dir.resolve(name);

                if (kind == ENTRY_CREATE) {
                    try {
                        if (Files.isDirectory(child)) {
                            walkAndRegisterDirectories(child);
                        }
                    } catch (IOException x) {
                        // do something useful
                    }
                }
                if (kind == ENTRY_DELETE) {
                    File deleteFile = new File(securePath + "\\" + event.context() + ".SCS");
                    deleteFile.delete();
                }
                boolean valid = key.reset();
                if (!valid) {
                    keys.remove(key);
                    // all directories are inaccessible
                    if (keys.isEmpty()) {
                        break;
                    }
                }
                String targetName = event.context().toString();

                File target_File = new File(String.valueOf(dir) + "\\" + targetName);
                try {
                    Recursion(target_File, event);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public static void Decrypt_Recrusion(@NotNull File file, String S_Path, String L_Path, String M_Path) {
        if (file.isDirectory()) {

            //폴더 안 파일들을 리스트 형태로 저장
            File[] list_file = file.listFiles();

            String New_L_Path = L_Path + "\\" + file.getName();
            File L_File = new File(New_L_Path);
            L_File.mkdirs();

            String New_S_Path = S_Path + "\\" + file.getName();

            //리스트 형태로 저장한 파일들을 recursion
            for (int i = 0; i < list_file.length; i++) {
                Decrypt_Recrusion(list_file[i], New_S_Path, New_L_Path, M_Path);

            }
        }
        //해당 파일이 파일일 경우
        if (file.isFile()) {
            try {
                decrypt(file.getName(), S_Path, L_Path, M_Path);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}