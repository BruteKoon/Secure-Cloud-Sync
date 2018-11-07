package org.securecloudsync.ui.controller;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.Pane;
import org.securecloudsync.filesystem.DetectThread;

import javax.swing.*;
import java.io.*;
import java.net.URL;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.ResourceBundle;
import java.util.StringTokenizer;

import static java.lang.Runtime.getRuntime;
import static org.securecloudsync.cryptolib.KeyManagement.genMasterKey;
import static org.securecloudsync.cryptolib.KeyManagement.makeMasterkeyFile;
import static org.securecloudsync.filesystem.DetectThread.Decrypt_Recrusion;
import static org.securecloudsync.filesystem.FileSystemImpl.plainFolderPath;
import static org.securecloudsync.ui.controller.FileListManagement.fileListWrite;
import static org.securecloudsync.ui.controller.FileListManagement.fileNamesha;
import static org.securecloudsync.ui.controller.LoginController.fileListName;

/**
 * 프로그램 실행 시, 주요 기능이 있는 화면 부분
 * 보관함 추가 / 마운트 / 언마운트와 같은 주요 기능 존재
 */
public class MainController implements Initializable {

    public SplitPane mainLayout;
    public AnchorPane rightLayout;
    public Pane changeLayout;
    public AnchorPane notfoundLayout;
    public AnchorPane unlockLayout;
    public AnchorPane lockLayout;
    public AnchorPane tutorialLayout;
    public AnchorPane usingLayout;
    public Button deleteFolderButton;
    public Label nongrouperr;
    ObservableList<String> listViewData;
    @FXML
    public ListView<String> listViewBox;

    //drive Mount, UnMount를 위한 변수
    public HashMap<String, String> Mount_Map = new HashMap<>();
    public String Drive_Name = "Z";
    public static int Mount_Flag = 0;

    public static byte[] f = {0x00};


    //경로 및 이름 받는 변수
    public String Master_Path;
    public static String Total_Path;
    public static String selectedFolderPlainPath;
    public String path;
    public String name;

    DetectThread DT;

    /**
     * 리스트에서 폴더정보를 불러옴
     * 리스트에 폴더 존재여부에 따라 UI 달라짐
     *
     * @param mouseEvent
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    public void didClickList(MouseEvent mouseEvent) throws IOException, NoSuchAlgorithmException {
        //경로 및 이름 설정을 위한 과정
        Total_Path = listViewBox.getSelectionModel().getSelectedItem();
        if (Total_Path == null) {
            return;
        }
        StringTokenizer tokens = new StringTokenizer(Total_Path);
        String tmp = tokens.nextToken("\\");
        while (tokens.hasMoreTokens()) {
            tmp = tokens.nextToken("\\");
        }
        int Total_num = Total_Path.length();
        int name_num = tmp.length();

        // 리스트에 해당하는 경로 및 이름 변수에 지정 (Mount에 쓰기 위함)
        path = Total_Path.substring(0, Total_num - name_num - 1);
        name = tmp;
        selectedFolderPlainPath = plainFolderPath + "\\" + fileNamesha(Total_Path) + name;
        //filelist의 목록과 실제 directory를 비교해서 false라면

        changeUI();
    }

    /**
     * 리스트에서 선택한 폴더를 마운트
     *
     * @param event
     * @throws Exception
     */
    public void didClickMount(ActionEvent event) {
        //드라이브 이름(아스키로 일단 입력 (일시적인것 ))
        int drive_name = 90;// ASCII "Z"

        //사용중인 드라이브 배열로 담기 위한 변수
        char[] tmp_drive = new char[10];

        //사용 중인 드라이브 이름 배열에 담기
        File[] roots = File.listRoots();
        int drive_num = 0;
        for (File root : roots) {
            tmp_drive[drive_num] = root.toString().charAt(0);
            drive_num = drive_num + 1;
        }

        //사용중인 이름 빼고, 사용할 드라이브 이름 정하기
        char ascii_drive_name = 0;
        while (0 < drive_num) {
            ascii_drive_name = (char) drive_name;
            if (tmp_drive[drive_num - 1] == ascii_drive_name) {
                drive_name = drive_name - 1;
            }
            drive_num = drive_num - 1;
        }

        //정한 이름 selected_drive_name에 넣기
        String selected_drive_name = new String(String.valueOf(ascii_drive_name));

        //외부 프로세스 사용하여 SUBST 명렁어 이용
        try {
            if (!(java.util.Arrays.equals(genMasterKey(Total_Path), f))) {
                String command = "SUBST " + selected_drive_name + ": " + selectedFolderPlainPath;
                //외부 프로세스 사용하여 command 사용
                try {
                    getRuntime().exec(command);
                    Mount_Map.put(selectedFolderPlainPath, selected_drive_name);
                    Mount_Flag = 1;
                    //마운트 한 폴더에 대해서 이벤트 탐지(스레드로 구성)
                    DT = new DetectThread(selectedFolderPlainPath, Total_Path);
                    DT.start();

                } catch (IOException e) {//오류 발생시 출력
                    e.printStackTrace();
                }
                lockLayout.setVisible(true);
                notfoundLayout.setVisible(false);
                unlockLayout.setVisible(false);
            } else {
                String src = Total_Path + "\\SCS";
                InputStream in = new FileInputStream(src);
                byte[] isGrup = new byte[1];
                in.read(isGrup);
                in.close();
                if (isGrup[0] == 0x00) {
                    nongrouperr.setVisible(true);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    /**
     * 리스트에서 선택한 폴더를 언마운트
     * 해당 폴더의 종류에 따라 UI변경
     * 일반 폴더, 공유폴더(리더, 일반)
     *
     * @param event
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    public void didClickUnMount(ActionEvent event) throws NoSuchAlgorithmException, IOException {
        //외부 프로세스 사용하여 SUBST 명렁어 이용
        Process p;
        String selected_drive_name = null;

        // 경로를 통해 Drive Name 가져오기
        selected_drive_name = Mount_Map.get(selectedFolderPlainPath);

        DT.interrupt();

        Mount_Flag = 0;
        //command 구성
        String command = "SUBST " + selected_drive_name + ": /d";

        //외부 프로세스 사용하여 command 사용(드라이브 언마운트)
        try {
            p = getRuntime().exec(command);
            Mount_Map.remove(selectedFolderPlainPath);

        } catch (IOException e) {//오류 발생시 출력
            e.printStackTrace();
        }

        lockLayout.setVisible(false);
        notfoundLayout.setVisible(false);
        deleteFolderButton.setDisable(false);
        unlockLayout.setVisible(true);

    }


    /**
     * 새폴더 추가
     *
     * @param event
     * @throws Exception
     */
    public void didClickAddNewFolder(ActionEvent event) throws Exception {
        JFrame window = new JFrame();
        JFileChooser fileChooser = new JFileChooser();

        //폴더오픈 다이얼로그 를 띄움
        int result = fileChooser.showOpenDialog(window);

        if (result == JFileChooser.APPROVE_OPTION) {
            //선택한 파일의 경로 반환
            File selectedFile = fileChooser.getSelectedFile();
            if (selectedFile.exists()) {
                //존재 시
                return;
            } else {
                selectedFile.mkdir(); // 폴더 생성
                makeMasterkeyFile(selectedFile, 0);

                //로컬 폴더 생성
                selectedFolderPlainPath = plainFolderPath + "\\" + fileNamesha(selectedFile.getPath()) + selectedFile.getName();
                //파일 객체 생성
                File file = new File(selectedFolderPlainPath);
                //!표를 붙여주어 파일이 존재하지 않는 경우의 조건을 걸어줌
                if (!file.exists()) {
                    //디렉토리 생성 메서드
                    file.mkdirs();
                }
                if (selectedFile.getName() == null) {
                } else {
                    fileListWrite(selectedFile);
                    listViewData.add(selectedFile.getParent() + "\\" + selectedFile.getName());
                    listViewBox.setItems(listViewData);
                }
            }
        }
    }

    /**
     * 폴더 리스트 업데이트
     *
     * @param location
     * @param resources
     */
    @Override
    public void initialize(URL location, ResourceBundle resources) {
        listViewData = FXCollections.observableArrayList();
        fileListRead();
        listViewBox.setItems(listViewData);
        listViewBox.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);
    }


    /**
     * filelist를 업데이트 하기 위해 fileList에서 폴더 리스트 읽어오기
     */
    public void fileListRead() {
        try {
            BufferedReader br = new BufferedReader(new FileReader(plainFolderPath + "\\" + fileListName));
            String line;

            while ((line = br.readLine()) != null) {
                String[] tmp = line.split("\\t", 2);
                listViewData.add(tmp[0]);
            }
            br.close();
        } catch (Exception e) {
        }
    }

    /**
     * 기존 보관함 추가
     *
     * @param event
     * @throws Exception
     */
    public void didClickAddExistFolder(ActionEvent event) throws Exception {
        JFrame window = new JFrame();
        JFileChooser fileChooser = new JFileChooser();
        //폴더 선택 가능
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

        //폴더오픈 다이얼로그 를 띄움
        int result = fileChooser.showOpenDialog(window);

        if (result == JFileChooser.APPROVE_OPTION) {
            //선택한 폴더
            File selectedFolder = fileChooser.getSelectedFile();
            Master_Path = selectedFolder.getPath();
            String folder_Name = selectedFolder.getName();


            // 폴더 안 탐색
            if (selectedFolder.listFiles().length == 0) { // 선택한 폴더가 빈폴더 일 경우
            } else {//안에 내용이 있을 경우
                File[] fileList = selectedFolder.listFiles();

                //폴더 내부의 파일 및 폴더에 대해 decrypt 적용
                for (int i = 0; i < fileList.length; i++) {
                    File file = fileList[i];

                    //master key가 있는 경우
                    if (file.getName().equals("SCS")) {
                        byte[] f = {0x00};
                        if (java.util.Arrays.equals(genMasterKey(selectedFolder.getPath()), f)) {
                            break;
                        }

                        //로컬 폴더 생성 과정
                        selectedFolderPlainPath = plainFolderPath + "\\" + fileNamesha(selectedFolder.getPath()) + folder_Name;
                        //파일 객체 생성
                        File l_file = new File(selectedFolderPlainPath);
                        //로컬 폴더 생성
                        if (!l_file.exists()) {
                            l_file.mkdirs();
                            //현재 구현된것은 기존 그대로 복사!
                            File[] copy_List = selectedFolder.listFiles();

                            //복호화 재귀함수 작동!
                            int k;
                            for (k = 0; k < copy_List.length; k = k + 1) {
                                File target_file = copy_List[k];
                                if (target_file.getName().equals("SCS")) {
                                    continue;
                                }
                                Decrypt_Recrusion(target_file, selectedFolder.getPath(), selectedFolderPlainPath, Master_Path);
                            }

                            //리스트 갱신(파일(txt)에 저장)
                            fileListWrite(selectedFolder);

                            //리스트 뷰 갱신
                            listViewData.add(String.valueOf(selectedFolder));
                            listViewBox.setItems(listViewData);
                        }
                    }
                }
            }
        }
    }

    /**
     * 해당 폴더 삭제
     *
     * @param event
     */
    public void didClickDeleteFolder(ActionEvent event) {
        //로컬 폴더 경로 설정
        String targetName = path + "\\" + name;

        //directory를 check하여 디렉토리와 리스트가 일치하다면 삭제

        //selectedFolderPlainPath : 기본으로 생성되는 문서폴더내의 CloudSync 하위의 path
        if ((checkDir(targetName)) == true) {
            directoryDelete(selectedFolderPlainPath);
            //파일 리스트 삭제 및 listView refresh
            fileListDelete(targetName);
            listViewBox.refresh();
        }

        notfoundLayout.setVisible(false);
        unlockLayout.setVisible(false);

        //Tutorial 설명하는 이미지 및 내용 false
        tutorialLayout.setVisible(true);
        deleteFolderButton.setDisable(false);

    }

    /**
     * 파일 리스트에서 해당 폴더 삭제 후 파일리스트UI 업데이트
     *
     * @param target
     */
    public void fileListDelete(String target) {
        int index, i = 0, c = 0;

        File file = new File(plainFolderPath + "\\" + fileListName);

        String temp = "";
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(file)));
            String line;
            while ((line = br.readLine()) != null) {
                i++;
                index = line.indexOf("\t");
                //target과 읽어온 filelist에 같은내용이 있으면
                if (target.equals(line.substring(0, index))) {
                    c = i;
                    temp += ""; //해당 라인삭제
                } else
                    temp += line + "\r\n";
            }
            br.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            FileWriter fw = new FileWriter(plainFolderPath + "\\" + fileListName);
            fw.write(temp); //위의 내용들을 write
            fw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        //해당되는 index 제거
        listViewData.remove(c - 1);

    }

    /**
     * 해당 디렉토리와 함께 그 안에있는 모든 파일 삭제
     *
     * @param target
     */
    public void directoryDelete(String target) {
        File file = new File(target);
        File[] tempFile = file.listFiles();

        //파일이 존재한다면 재귀적으로 하위 폴더까지 삭제함

        if (file.exists()) {
            if (tempFile.length > 0) {
                for (int i = 0; i < tempFile.length; i++) {
                    //File일 경우 전부 삭제
                    if (tempFile[i].isFile()) {
                        System.gc();
                        tempFile[i].delete();
                    }
                    //directory일 경우 재귀를 이용하여 하위 디렉토리로 이동
                    else if (tempFile[i].isDirectory()) {
                        directoryDelete(tempFile[i].getPath());
                    }
                    //모두 끝날경우 해당 directory 삭제
                    System.gc();
                    tempFile[i].delete();
                }
            }
            //최상위 디렉토리(list에 있는 디렉토리) 삭제
            System.gc();
            file.delete();
        }
        //파일이 존재하지 않으면 그냥 return
        else
            return;
    }

    private void changeUI() throws NoSuchAlgorithmException, IOException {
        if (!directoryCheck(name)) {
            lockLayout.setVisible(false);
            unlockLayout.setVisible(false);
            notfoundLayout.setVisible(true);
            deleteFolderButton.setDisable(false);
            usingLayout.setVisible(false);
        }
        //일치하는 경우
        else {
            //UI 변경 ( 마운트 하기 위함)
            if (Mount_Flag == 1) { //마운트 됬다.
                if (Mount_Map.containsKey(selectedFolderPlainPath)) {//
                    lockLayout.setVisible(true);
                    unlockLayout.setVisible(false);
                    notfoundLayout.setVisible(false);
                    usingLayout.setVisible(false);
                } else {
                    lockLayout.setVisible(false);
                    usingLayout.setVisible(true);

                }
            } else {
                lockLayout.setVisible(false);
                notfoundLayout.setVisible(false);
                unlockLayout.setVisible(true);
            }
        }
        //Tutorial 설명하는 이미지 및 내용 false
        tutorialLayout.setVisible(false);
        deleteFolderButton.setDisable(false);
    }

    /**
     * 선택한 폴더가 존재하는지 확인
     *
     * @param target 선택한 폴더
     * @return (boolean) 있는지 여부
     */
    private boolean directoryCheck(String target) {
        int result = 0;
        Path p = Paths.get(path);

        DirectoryStream<Path> dir = null;
        try {
            dir = Files.newDirectoryStream(p);
            for (Path file : dir) {
                if (target.equals(file.getFileName().toString())) {
                    result = 1;
                    break;
                } else {
                    result = 0;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        //찾았을경우 return true
        if (result == 1)
            return true;
        else
            return false;
    }

    private boolean checkDir(String target) {
        int result = 0;
        Path p = Paths.get(path);

        DirectoryStream<Path> dir = null;
        try {
            dir = Files.newDirectoryStream(p);
            for (Path file : dir) {
                //if (target.equals(file.getFileName().toString())) {
                if (target.equals(file.toString())) {
                    result = 1;
                    break;
                } else {
                    result = 0;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        //찾았을경우 return true
        if (result == 1)
            return true;
        else
            return false;
    }
}