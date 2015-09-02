package eu.europa.esig.dss.standalone.controller;

import java.net.URL;
import java.util.ResourceBundle;

import javafx.beans.binding.BooleanBinding;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.RadioButton;
import javafx.scene.control.Toggle;
import javafx.scene.control.ToggleGroup;
import javafx.scene.layout.HBox;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureTokenType;
import eu.europa.esig.dss.standalone.DSSApplication;
import eu.europa.esig.dss.standalone.fx.TypedToggleGroup;
import eu.europa.esig.dss.standalone.model.SignatureModel;

public class SignatureController implements Initializable {

	@FXML
	private ToggleGroup toogleSigFormat;

	@FXML
	private TypedToggleGroup<SignatureForm> toggleAsicUnderlying;

	@FXML
	private TypedToggleGroup<SignaturePackaging> toggleSigPackaging;

	@FXML
	private RadioButton envelopedRadio;

	@FXML
	private RadioButton envelopingRadio;

	@FXML
	private RadioButton detachedRadio;

	@FXML
	private ComboBox<SignatureLevel> comboLevel;

	@FXML
	private TypedToggleGroup<DigestAlgorithm> toggleDigestAlgo;

	@FXML
	private TypedToggleGroup<SignatureTokenType> toggleSigToken;

	@FXML
	private HBox hUnderlyingSignatureFormat;

	@FXML
	private HBox hPkcsFile;

	@FXML
	private Label labelPkcs11File;

	@FXML
	private Label labelPkcs12File;

	@FXML
	private HBox hPkcsPassword;

	private DSSApplication dssApplication;

	private SignatureModel model;

	public void setApp(DSSApplication dssApplication) {
		this.dssApplication = dssApplication;
	}

	@Override
	public void initialize(URL location, ResourceBundle resources) {
		model = new SignatureModel();

		hUnderlyingSignatureFormat.managedProperty().bind(hUnderlyingSignatureFormat.visibleProperty());
		hPkcsFile.managedProperty().bind(hPkcsFile.visibleProperty());
		hPkcsPassword.managedProperty().bind(hPkcsPassword.visibleProperty());
		labelPkcs11File.managedProperty().bind(labelPkcs11File.visibleProperty());
		labelPkcs12File.managedProperty().bind(labelPkcs12File.visibleProperty());

		toogleSigFormat.selectedToggleProperty().addListener(new ChangeListener<Toggle>() {
			@Override
			public void changed(ObservableValue<? extends Toggle> observable, Toggle oldValue, Toggle newValue) {
				SignatureForm signatureForm = null;
				if (newValue != null) {
					signatureForm = SignatureForm.valueOf((String) newValue.getUserData());
				}
				updateSignatureForm(signatureForm);
			}
		});

		toggleAsicUnderlying.getSelectedValueProperty().bindBidirectional(model.asicUnderlyingFormProperty());
		toggleSigPackaging.getSelectedValueProperty().bindBidirectional(model.signaturePackagingProperty());
		toggleDigestAlgo.getSelectedValueProperty().bindBidirectional(model.digestAlgorithmProperty());

		comboLevel.valueProperty().addListener(new ChangeListener<SignatureLevel>() {
			@Override
			public void changed(ObservableValue<? extends SignatureLevel> observable, SignatureLevel oldValue, SignatureLevel newValue) {
				model.setSignatureLevel(newValue);
			}
		});

		toggleSigToken.getSelectedValueProperty().bindBidirectional(model.tokenTypeProperty());

		BooleanBinding isPkcs11Or12 = model.tokenTypeProperty().isEqualTo(SignatureTokenType.PKCS11)
				.or(model.tokenTypeProperty().isEqualTo(SignatureTokenType.PKCS12));

		hPkcsFile.visibleProperty().bind(isPkcs11Or12);
		hPkcsPassword.visibleProperty().bind(isPkcs11Or12);

		labelPkcs11File.visibleProperty().bind(model.tokenTypeProperty().isEqualTo(SignatureTokenType.PKCS11));
		labelPkcs12File.visibleProperty().bind(model.tokenTypeProperty().isEqualTo(SignatureTokenType.PKCS12));
	}


	protected void updateSignatureForm(SignatureForm signatureForm) {
		model.setSignatureForm(signatureForm);

		if (SignatureForm.ASiC_S.equals(signatureForm) || SignatureForm.ASiC_E.equals(signatureForm)) {

			//			hUnderlyingSignatureFormat.visibleProperty().bind(model.digestAlgorithmProperty().);

			hUnderlyingSignatureFormat.setVisible(true);
		} else {
			hUnderlyingSignatureFormat.setVisible(false);
			model.setAsicUnderlyingForm(null);
		}

		reinitSignaturePackagings();

		comboLevel.setDisable(false);
		comboLevel.getItems().removeAll(comboLevel.getItems());

		if (signatureForm != null) {
			switch (signatureForm) {
				case CAdES:
					envelopingRadio.setDisable(false);
					detachedRadio.setDisable(false);

					comboLevel.itemsProperty().set(
							FXCollections.observableArrayList(SignatureLevel.CAdES_BASELINE_B, SignatureLevel.CAdES_BASELINE_T, SignatureLevel.CAdES_BASELINE_LT,
									SignatureLevel.CAdES_BASELINE_LTA));
					comboLevel.setValue(SignatureLevel.CAdES_BASELINE_B);
					break;
				case PAdES:
					envelopedRadio.setDisable(false);

					envelopedRadio.setSelected(true);

					comboLevel.getItems().addAll(SignatureLevel.PAdES_BASELINE_B, SignatureLevel.PAdES_BASELINE_T, SignatureLevel.PAdES_BASELINE_LT,
							SignatureLevel.PAdES_BASELINE_LTA);
					comboLevel.setValue(SignatureLevel.PAdES_BASELINE_B);
					break;
				case XAdES:
					envelopingRadio.setDisable(false);
					envelopedRadio.setDisable(false);
					detachedRadio.setDisable(false);

					comboLevel.getItems().addAll(SignatureLevel.XAdES_BASELINE_B, SignatureLevel.XAdES_BASELINE_T, SignatureLevel.XAdES_BASELINE_LT,
							SignatureLevel.XAdES_BASELINE_LTA);
					comboLevel.setValue(SignatureLevel.XAdES_BASELINE_B);
					break;
				case ASiC_S:
					detachedRadio.setDisable(false);

					detachedRadio.setSelected(true);

					comboLevel.getItems().addAll(SignatureLevel.ASiC_S_BASELINE_B, SignatureLevel.ASiC_S_BASELINE_T, SignatureLevel.ASiC_S_BASELINE_LT,
							SignatureLevel.ASiC_S_BASELINE_LTA);
					comboLevel.setValue(SignatureLevel.ASiC_S_BASELINE_B);
					break;
				case ASiC_E:
					detachedRadio.setDisable(false);

					detachedRadio.setSelected(true);

					comboLevel.getItems().addAll(SignatureLevel.ASiC_E_BASELINE_B, SignatureLevel.ASiC_E_BASELINE_T, SignatureLevel.ASiC_E_BASELINE_LT,
							SignatureLevel.ASiC_E_BASELINE_LTA);
					comboLevel.setValue(SignatureLevel.ASiC_E_BASELINE_B);
					break;
				default:
					break;
			}
		}

	}

	private void reinitSignaturePackagings() {
		envelopingRadio.setDisable(true);
		envelopedRadio.setDisable(true);
		detachedRadio.setDisable(true);

		envelopingRadio.setSelected(false);
		envelopedRadio.setSelected(false);
		detachedRadio.setSelected(false);
	}

}
