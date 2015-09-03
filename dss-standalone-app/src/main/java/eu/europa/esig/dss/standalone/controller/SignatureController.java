package eu.europa.esig.dss.standalone.controller;

import java.io.File;
import java.net.URL;
import java.util.ResourceBundle;

import javafx.beans.binding.BooleanBinding;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.RadioButton;
import javafx.scene.layout.HBox;
import javafx.stage.FileChooser;
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
	private Button fileSelectButton;

	@FXML
	private TypedToggleGroup<SignatureForm> toogleSigFormat;

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

	@FXML
	private Button pkcsFileButton;

	@FXML
	private PasswordField pkcsPassword;

	@FXML
	private Button signButton;

	private DSSApplication dssApplication;

	private SignatureModel model;

	public void setApp(DSSApplication dssApplication) {
		this.dssApplication = dssApplication;
	}

	@Override
	public void initialize(URL location, ResourceBundle resources) {
		model = new SignatureModel();

		// Allows to collapse items
		hUnderlyingSignatureFormat.managedProperty().bind(hUnderlyingSignatureFormat.visibleProperty());
		hPkcsFile.managedProperty().bind(hPkcsFile.visibleProperty());
		hPkcsPassword.managedProperty().bind(hPkcsPassword.visibleProperty());
		labelPkcs11File.managedProperty().bind(labelPkcs11File.visibleProperty());
		labelPkcs12File.managedProperty().bind(labelPkcs12File.visibleProperty());

		fileSelectButton.setOnAction(new EventHandler<ActionEvent>() {
			@Override
			public void handle(ActionEvent event) {
				FileChooser fileChooser = new FileChooser();
				fileChooser.setTitle("File to sign");
				File fileToSign = fileChooser.showOpenDialog(dssApplication.getStage());
				model.setFileToSign(fileToSign);
				if (fileToSign != null) {
					fileSelectButton.setText(fileToSign.getName());
				} else {
					fileSelectButton.setText("Select file...");
				}
			}
		});

		// Enables / disables options with selected signature form
		toogleSigFormat.getSelectedValueProperty().addListener(new ChangeListener<SignatureForm>() {
			@Override
			public void changed(ObservableValue<? extends SignatureForm> observable, SignatureForm oldValue, SignatureForm newValue) {
				updateSignatureForm(newValue);
			}
		});

		// Displays underlying format in case of ASiC
		BooleanBinding isASiC = model.signatureFormProperty().isEqualTo(SignatureForm.ASiC_S).or(model.signatureFormProperty().isEqualTo(SignatureForm.ASiC_E));
		hUnderlyingSignatureFormat.visibleProperty().bind(isASiC);

		// Binds values with model
		toggleAsicUnderlying.getSelectedValueProperty().bindBidirectional(model.asicUnderlyingFormProperty());
		toggleSigPackaging.getSelectedValueProperty().bindBidirectional(model.signaturePackagingProperty());
		toggleDigestAlgo.getSelectedValueProperty().bindBidirectional(model.digestAlgorithmProperty());
		comboLevel.valueProperty().bindBidirectional(model.signatureLevelProperty());
		toggleSigToken.getSelectedValueProperty().bindBidirectional(model.tokenTypeProperty());

		toggleSigToken.getSelectedValueProperty().addListener(new ChangeListener<SignatureTokenType>() {
			@Override
			public void changed(ObservableValue<? extends SignatureTokenType> observable, SignatureTokenType oldValue, SignatureTokenType newValue) {
				model.setPkcsFile(null);
				model.setPassword(null);
			}
		});

		pkcsFileButton.setOnAction(new EventHandler<ActionEvent>() {
			@Override
			public void handle(ActionEvent event) {
				FileChooser fileChooser = new FileChooser();
				if (SignatureTokenType.PKCS11.equals(model.getTokenType())) {
					fileChooser.setTitle("Library");
				} else if (SignatureTokenType.PKCS12.equals(model.getTokenType())) {
					fileChooser.setTitle("Keystore");
				}
				File pkcsFile = fileChooser.showOpenDialog(dssApplication.getStage());
				model.setPkcsFile(pkcsFile);
				if (pkcsFile != null) {
					pkcsFileButton.setText(pkcsFile.getName());
				} else {
					pkcsFileButton.setText("Select file...");
				}
			}
		});

		pkcsPassword.textProperty().bindBidirectional(model.passwordProperty());

		BooleanBinding isPkcs11Or12 = model.tokenTypeProperty().isEqualTo(SignatureTokenType.PKCS11).or(model.tokenTypeProperty().isEqualTo(SignatureTokenType.PKCS12));

		hPkcsFile.visibleProperty().bind(isPkcs11Or12);
		hPkcsPassword.visibleProperty().bind(isPkcs11Or12);

		labelPkcs11File.visibleProperty().bind(model.tokenTypeProperty().isEqualTo(SignatureTokenType.PKCS11));
		labelPkcs12File.visibleProperty().bind(model.tokenTypeProperty().isEqualTo(SignatureTokenType.PKCS12));

		BooleanBinding isMandatoryFieldsEmpty = model.fileToSignProperty().isNull()
				.or(model.signatureFormProperty().isNull())
				.or(model.signaturePackagingProperty().isNull())
				.or(model.digestAlgorithmProperty().isNull())
				.or(model.tokenTypeProperty().isNull());

		BooleanBinding isUnderlyingEmpty = model.signatureFormProperty().isEqualTo(SignatureForm.ASiC_S).or(model.signatureFormProperty().isEqualTo(SignatureForm.ASiC_E))
				.and(model.asicUnderlyingFormProperty().isNull());

		BooleanBinding isEmptyFileOrPassword = model.pkcsFileProperty().isNull().or(model.passwordProperty().isEmpty());

		BooleanBinding isPKCSIncomplete = model.tokenTypeProperty().isEqualTo(SignatureTokenType.PKCS11).or(model.tokenTypeProperty().isEqualTo(SignatureTokenType.PKCS12))
				.and(isEmptyFileOrPassword);

		signButton.disableProperty().bind(isMandatoryFieldsEmpty.or(isUnderlyingEmpty).or(isPKCSIncomplete));

		signButton.setOnAction(new EventHandler<ActionEvent>() {
			@Override
			public void handle(ActionEvent event) {
				System.out.println("Signing....");
			}
		});
	}

	protected void updateSignatureForm(SignatureForm signatureForm) {
		model.setSignatureForm(signatureForm);

		reinitSignaturePackagings();

		comboLevel.setDisable(false);
		comboLevel.getItems().removeAll(comboLevel.getItems());

		if (signatureForm != null) {
			switch (signatureForm) {
				case CAdES:
					envelopingRadio.setDisable(false);
					detachedRadio.setDisable(false);

					comboLevel.getItems().addAll(SignatureLevel.CAdES_BASELINE_B, SignatureLevel.CAdES_BASELINE_T, SignatureLevel.CAdES_BASELINE_LT,
							SignatureLevel.CAdES_BASELINE_LTA);
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
