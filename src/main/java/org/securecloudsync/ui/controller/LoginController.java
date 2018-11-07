package org.securecloudsync.ui.controller;

import javafx.event.ActionEvent;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.layout.Pane;

import static org.securecloudsync.ui.controller.ViewController.showMainController;

/**
 * 프로그램 실행 시 첫 페이지 부분
 * 비밀번호를 통해서 실행
 */
public class LoginController {

    public static byte[] folderPaasword;
    public static String fileListName = "fileList";

    public Pane folderPasswdLayout;
    public PasswordField folderpasswd;
    public Label checkPasswd;

    public void didClickStartButton(ActionEvent event) throws Exception {
        folderPaasword = getFolderPasswd().getText().getBytes();
            showMainController();
    }

    private PasswordField getFolderPasswd() {
        return folderpasswd;
    }
}
