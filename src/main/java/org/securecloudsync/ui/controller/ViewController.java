package org.securecloudsync.ui.controller;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.BorderPane;
import javafx.stage.Stage;

import java.io.*;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Main class
 * 프로그램의 뷰를 전체적으로 구성
 * */
public class ViewController extends Application {
    private static Stage primaryStage;
    private static BorderPane rootLayout;
    //private Pane loginPage = LoginController.loginPage;
    final static byte[] png1 = {126, -47, -120, -103, -17, 39, -27, 77, -84, 14, -29, 10, 70, 121, 1, -5, -76, -44, -37, -12, -46, -120, 109, 29, 107, -83, -19, -29, -40, -22, 63, 6};
    final static byte[] png2 = {108, 123, -5, -10, 71, 56, 91, -34, 100, -1, -124, -118, 118, 99, -44, 98, 112, -10, -63, 84, -5, -41, 123, 81, -8, 35, 64, 9, -127, 17, 40, -59};
    final static byte[] fxml1 = {-40, -46, 13, -20, -111, 124, 31, -10, 73, -54, -10, 101, -15, 66, 102, 60, 103, -75, 56, -44, 96, 80, 23, -124, -99, -53, 82, -110, -71, -87, -94, -84};
    final static byte[] fmxl2 = {-106, 125, 16, 101, 7, 92, -93, 103, -5, -10, 84, -33, -94, -15, 79, 41, -17, 103, -2, 22, 120, 28, -114, -103, -39, 117, 24, -55, -127, -1, -9, -116};
    final static byte[] fxml3 = {-67, -6, -19, -13, -33, 42, -93, 112, 3, -86, -74, -112, -82, 53, 118, -36, 110, 82, -33, 97, 105, 67, 59, -30, 101, 34, 33, -3, 90, 58, 85, 97};

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        launch(args);
    }


    public static byte[] SHA256(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(input);
    }

    @Override
    public void start(Stage primaryStage) throws UnsupportedEncodingException {

        this.primaryStage = primaryStage;
        //Title
        this.primaryStage.setTitle("Cloud Service Sync");
        //Logo
        this.primaryStage.getIcons().add(new Image(getClass().getResource("/fxml/img/securecloudsync.png").toExternalForm()));

        hashcheck();

        //크기 조절 불가
        this.primaryStage.setResizable(false);

        initRootLayout();
        showFolderPaaswdController();
    }

    public void hashcheck() {
        hashcheck("/fxml/img/securecloudsync.png", png1);
        hashcheck("/fxml/img/change.png", png2);
        hashcheck("/fxml/FolderPasswdInput.fxml", fxml1);
        hashcheck("/fxml/Main.fxml", fmxl2);
        hashcheck("/fxml/MainLayout.fxml", fxml3);
    }

    public void hashcheck(String target, byte[] hash) {
        URL res = getClass().getResource(target);
        if (res.toString().startsWith("jar:")) {
            try {
                InputStream input = getClass().getResourceAsStream(target);
                int size = 0;
                int chunk = 0;
                byte[] bytes = new byte[4096];

                while ((chunk = input.read(bytes)) != -1) {
                    size += chunk;
                }
                byte[] sizeBytes = new byte[size];
                input.read(sizeBytes);
                byte[] output = SHA256(sizeBytes);
                if (!Arrays.equals(output, hash)) {

                   System.exit(0);
                }
            } catch (IOException ex) {
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
    }

    public static void initRootLayout() {
        try {
            FXMLLoader loader = new FXMLLoader();
            loader.setLocation(ViewController.class.getResource("/fxml/MainLayout.fxml"));

            rootLayout = loader.load();

            Scene scene = new Scene(rootLayout);

            primaryStage.setScene(scene);
            primaryStage.show();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void showFolderPaaswdController() {
        try {
            FXMLLoader loader = new FXMLLoader();
            loader.setLocation(ViewController.class.getResource("/fxml/FolderPasswdInput.fxml"));
            AnchorPane personOverview = loader.load();

            rootLayout.setCenter(personOverview);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void showMainController() {
        try {
            FXMLLoader loader = new FXMLLoader();
            loader.setLocation(ViewController.class.getResource("/fxml/Main.fxml"));
            AnchorPane personOverview = loader.load();

            rootLayout.setCenter(personOverview);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
