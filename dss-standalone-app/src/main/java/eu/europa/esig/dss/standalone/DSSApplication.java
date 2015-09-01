package eu.europa.esig.dss.standalone;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;

public class DSSApplication extends Application {

	@Override
	public void start(Stage stage) throws Exception {
		stage.setTitle("Digital Signature Service Application");
		Pane pane = FXMLLoader.load(DSSApplication.class.getResource("/fxml/screen.fxml"));

		Scene scene = new Scene(pane);
		scene.getStylesheets().add("/styles/style.css");
		stage.setScene(scene);
		stage.show();
	}

	public static void main(String[] args) {
		launch(DSSApplication.class, args);
	}

}
