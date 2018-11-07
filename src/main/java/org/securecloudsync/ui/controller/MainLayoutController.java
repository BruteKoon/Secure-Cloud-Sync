package org.securecloudsync.ui.controller;

import javafx.event.ActionEvent;

import static org.securecloudsync.ui.controller.MainController.Mount_Flag;
import static org.securecloudsync.ui.controllers.PopupController.wrongPopup;

/**
 * 프로그램의 레이아웃 담당
 */
public class MainLayoutController extends LoginController {

    public void didClickReinput(ActionEvent actionEvent) {
        if (Mount_Flag == 1) {
            wrongPopup("Please, unmount the folder");
        } else {
            ViewController.initRootLayout();
            ViewController.showMainController();
            ViewController.showFolderPaaswdController();
        }
    }
}
