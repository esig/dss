package eu.europa.esig.dss.standalone;

import javafx.application.Application;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.standalone.controller.SignatureController;

public class DSSApplication extends Application {

	private static Logger logger = LoggerFactory.getLogger(DSSApplication.class);

	private Stage stage;

	private ObservableList<DigestAlgorithm> availableDigestAlgos = FXCollections.observableArrayList();

	public DSSApplication() {
		availableDigestAlgos.add(DigestAlgorithm.SHA1);
		availableDigestAlgos.add(DigestAlgorithm.SHA224);
		availableDigestAlgos.add(DigestAlgorithm.SHA256);
		availableDigestAlgos.add(DigestAlgorithm.SHA384);
		availableDigestAlgos.add(DigestAlgorithm.SHA512);
	}

	@Override
	public void start(Stage stage) {
		this.stage = stage;
		this.stage.setTitle("Digital Signature Service Application");

		initLayout();

	}

	private void initLayout() {
		try {
			FXMLLoader loader = new FXMLLoader();
			loader.setLocation(DSSApplication.class.getResource("/fxml/screen.fxml"));
			Pane pane = loader.load();

			Scene scene = new Scene(pane);
			scene.getStylesheets().add("/styles/style.css");
			stage.setScene(scene);
			stage.show();

			SignatureController controller = loader.getController();
		} catch (Exception e) {
			logger.error("Unable to init layout : " + e.getMessage(), e);
		}
	}

	public static void main(String[] args) {
		launch(DSSApplication.class, args);
	}

	public ObservableList<DigestAlgorithm> getAvailableDigestAlgos() {
		return availableDigestAlgos;
	}

}
