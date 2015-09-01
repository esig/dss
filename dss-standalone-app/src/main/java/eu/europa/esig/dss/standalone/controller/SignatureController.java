package eu.europa.esig.dss.standalone.controller;

import java.net.URL;
import java.util.ResourceBundle;

import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.RadioButton;
import javafx.scene.control.Toggle;
import javafx.scene.control.ToggleGroup;

public class SignatureController implements Initializable {

	@FXML
	private ToggleGroup toggleDigestAlgo;

	@Override
	public void initialize(URL location, ResourceBundle resources) {

		toggleDigestAlgo.selectedToggleProperty().addListener(new ChangeListener<Toggle>() {

			@Override
			public void changed(ObservableValue<? extends Toggle> observable, Toggle oldValue, Toggle newValue) {
				if (toggleDigestAlgo.getSelectedToggle() != null) {

					RadioButton radio = (RadioButton) toggleDigestAlgo.getSelectedToggle();
					System.out.println(radio.getText());

					System.out.println("new -> " + newValue.toggleGroupProperty());
				}

			}
		});
	}

}
