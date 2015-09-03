package eu.europa.esig.dss.standalone.controller;

import java.io.File;
import java.io.FileOutputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.Set;

import javafx.beans.binding.BooleanBinding;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.ChoiceDialog;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.RadioButton;
import javafx.scene.layout.HBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.io.IOUtils;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureTokenType;
import eu.europa.esig.dss.standalone.fx.TypedToggleGroup;
import eu.europa.esig.dss.standalone.model.SignatureModel;
import eu.europa.esig.dss.standalone.service.SignatureService;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.x509.CertificateToken;

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

	private Stage stage;

	private SignatureModel model;

	private SignatureService signatureService;

	public void setStage(Stage stage) {
		this.stage = stage;
	}

	public void setSignatureService(SignatureService signatureService) {
		this.signatureService = signatureService;
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
				File fileToSign = fileChooser.showOpenDialog(stage);
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
				File pkcsFile = fileChooser.showOpenDialog(stage);
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

		BooleanBinding isMandatoryFieldsEmpty = model.fileToSignProperty().isNull().or(model.signatureFormProperty().isNull()).or(model.signaturePackagingProperty().isNull())
				.or(model.digestAlgorithmProperty().isNull()).or(model.tokenTypeProperty().isNull());

		BooleanBinding isUnderlyingEmpty = model.signatureFormProperty().isEqualTo(SignatureForm.ASiC_S).or(model.signatureFormProperty().isEqualTo(SignatureForm.ASiC_E))
				.and(model.asicUnderlyingFormProperty().isNull());

		BooleanBinding isEmptyFileOrPassword = model.pkcsFileProperty().isNull().or(model.passwordProperty().isEmpty());

		BooleanBinding isPKCSIncomplete = model.tokenTypeProperty().isEqualTo(SignatureTokenType.PKCS11).or(model.tokenTypeProperty().isEqualTo(SignatureTokenType.PKCS12))
				.and(isEmptyFileOrPassword);

		signButton.disableProperty().bind(isMandatoryFieldsEmpty.or(isUnderlyingEmpty).or(isPKCSIncomplete));

		signButton.setOnAction(new EventHandler<ActionEvent>() {
			@Override
			public void handle(ActionEvent event) {
				sign();
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

	private void sign() {
		SignatureTokenConnection token = signatureService.getToken(model);
		List<DSSPrivateKeyEntry> keys = token.getKeys();

		DSSDocument signedDocument = null;
		if (CollectionUtils.isEmpty(keys)) {
			Alert alert = new Alert(AlertType.WARNING, "No certificate found", ButtonType.CLOSE);
			alert.showAndWait();
			return;
		} else if (CollectionUtils.size(keys) == 1) {
			signedDocument = signatureService.sign(model, token, keys.get(0));
		} else {

			Map<String, DSSPrivateKeyEntry> map = new HashMap<String, DSSPrivateKeyEntry>();
			for (DSSPrivateKeyEntry dssPrivateKeyEntry : keys) {
				CertificateToken certificate = dssPrivateKeyEntry.getCertificate();
				String text = certificate.getSubjectShortName() + " (" + certificate.getSerialNumber() + ")";
				map.put(text, dssPrivateKeyEntry);
			}

			Set<String> keySet = map.keySet();
			ChoiceDialog<String> dialog = new ChoiceDialog<String>(keySet.iterator().next(), keySet);
			dialog.setHeaderText("Select your certificate");
			Optional<String> result = dialog.showAndWait();

			if (result.isPresent()) {
				String mapKey = result.get();
				signedDocument = signatureService.sign(model, token, map.get(mapKey));
			}
		}

		if (signedDocument != null) {
			FileChooser fileChooser = new FileChooser();
			File fileToSave = fileChooser.showSaveDialog(stage);
			if (fileToSave != null) {
				try {
					FileOutputStream fos = new FileOutputStream(fileToSave);
					IOUtils.write(signedDocument.getBytes(), fos);
					IOUtils.closeQuietly(fos);
				} catch (Exception e) {
					Alert alert = new Alert(AlertType.ERROR, "Unable to save file : " + e.getMessage(), ButtonType.CLOSE);
					alert.showAndWait();
					return;
				}

			}
		}
	}

}
