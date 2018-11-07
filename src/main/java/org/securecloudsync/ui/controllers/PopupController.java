package org.securecloudsync.ui.controllers;

import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

/**
 * 프로그램 버튼 실행 시, 나오는 팝업을 전체적으로 담당
 */
public class PopupController {

    public static void wrongPopup(String content) {

        if (Platform.isFxApplicationThread()) {
            final Stage s = new Stage();
            VBox v = new VBox();
            Button button = new Button("EXIT");
            s.setWidth(300);
            s.setHeight(200);
            v.setAlignment(Pos.CENTER);
            Label gap2 = new Label("");
            gap2.setMaxSize(25, 0);
            button.setOnAction(new EventHandler<ActionEvent>() {
                @Override
                public void handle(ActionEvent event) {

                    s.close();
                }
            });
            v.setPadding(new Insets(0, 0, 0, 0));
            v.getChildren().addAll(new Label(content), gap2, button);
            Scene sc = new Scene(v);
            s.setTitle("Error Message");
            s.setScene(sc);
            s.show();
        }
    }
}
