package eu.europa.esig.dss.standalone.controller;

import java.io.File;
import java.io.FileOutputStream;
import java.net.URL;
import java.util.ResourceBundle;

import eu.europa.esig.dss.ASiCContainerType;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.RemoteSignatureParameters;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureTokenType;
import eu.europa.esig.dss.signature.RemoteDocumentSignatureService;
import eu.europa.esig.dss.standalone.fx.FileToStringConverter;
import eu.europa.esig.dss.standalone.fx.TypedToggleGroup;
import eu.europa.esig.dss.standalone.model.SignatureModel;
import eu.europa.esig.dss.standalone.task.SigningTask;
import eu.europa.esig.dss.utils.Utils;
import javafx.beans.binding.BooleanBinding;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.concurrent.Service;
import javafx.concurrent.Task;
import javafx.concurrent.WorkerStateEvent;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ProgressIndicator;
import javafx.scene.control.RadioButton;
import javafx.scene.layout.HBox;
import javafx.stage.FileChooser;
import javafx.stage.FileChooser.ExtensionFilter;
import javafx.stage.Stage;

public class SignatureController implements Initializable {

	@FXML
	private Button fileSelectButton;

	@FXML
	private TypedToggleGroup<ASiCContainerType> toggleAsicContainerType;

	@FXML
	private TypedToggleGroup<SignatureForm> toogleSigFormat;

	@FXML
	private TypedToggleGroup<SignaturePackaging> toggleSigPackaging;

	@FXML
	private RadioButton cadesRadio;

	@FXML
	private RadioButton padesRadio;

	@FXML
	private RadioButton xadesRadio;

	@FXML
	private HBox hSignaturePackaging;

	@FXML
	private RadioButton envelopedRadio;

	@FXML
	private RadioButton envelopingRadio;

	@FXML
	private RadioButton detachedRadio;

	@FXML
	private ComboBox<SignatureLevel> comboLevel;

	@FXML
	private Label warningLabel;

	@FXML
	private TypedToggleGroup<DigestAlgorithm> toggleDigestAlgo;

	@FXML
	private TypedToggleGroup<SignatureTokenType> toggleSigToken;

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

	@FXML
	private ProgressIndicator progressSign;

	private Stage stage;

	private SignatureModel model;

	private RemoteDocumentSignatureService<RemoteDocument, RemoteSignatureParameters> signatureService;

	static {
		// Fix a freeze in Windows 10, JDK 8 and touchscreen
		System.setProperty("glass.accessible.force", "false");
	}

	public void setStage(Stage stage) {
		this.stage = stage;
	}

	public void setSignatureService(RemoteDocumentSignatureService<RemoteDocument, RemoteSignatureParameters> signatureService) {
		this.signatureService = signatureService;
	}

	@Override
	public void initialize(URL location, ResourceBundle resources) {
		model = new SignatureModel();

		// Allows to collapse items
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
			}
		});
		fileSelectButton.textProperty().bindBidirectional(model.fileToSignProperty(), new FileToStringConverter());

		// Enables / disables options with selected signature form
		toogleSigFormat.getSelectedValueProperty().addListener(new ChangeListener<SignatureForm>() {
			@Override
			public void changed(ObservableValue<? extends SignatureForm> observable, SignatureForm oldValue, SignatureForm newValue) {
				updateSignatureForm(newValue);
			}
		});

		toggleAsicContainerType.getSelectedValueProperty().addListener(new ChangeListener<ASiCContainerType>() {

			@Override
			public void changed(ObservableValue<? extends ASiCContainerType> observable, ASiCContainerType oldValue, ASiCContainerType newValue) {
				updateSignatureFormForASiC(newValue);
			}
		});

		// Binds values with model
		toggleAsicContainerType.getSelectedValueProperty().bindBidirectional(model.asicContainerTypeProperty());
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
			}
		});
		pkcsFileButton.textProperty().bindBidirectional(model.pkcsFileProperty(), new FileToStringConverter());

		pkcsPassword.textProperty().bindBidirectional(model.passwordProperty());

		BooleanBinding isPkcs11Or12 = model.tokenTypeProperty().isEqualTo(SignatureTokenType.PKCS11)
				.or(model.tokenTypeProperty().isEqualTo(SignatureTokenType.PKCS12));

		hPkcsFile.visibleProperty().bind(isPkcs11Or12);
		hPkcsPassword.visibleProperty().bind(isPkcs11Or12);

		labelPkcs11File.visibleProperty().bind(model.tokenTypeProperty().isEqualTo(SignatureTokenType.PKCS11));
		labelPkcs12File.visibleProperty().bind(model.tokenTypeProperty().isEqualTo(SignatureTokenType.PKCS12));

		BooleanBinding isMandatoryFieldsEmpty = model.fileToSignProperty().isNull().or(model.signatureFormProperty().isNull())
				.or(model.digestAlgorithmProperty().isNull()).or(model.tokenTypeProperty().isNull());

		BooleanBinding isASiCorPackagingPresent = model.asicContainerTypeProperty().isNull().and(model.signaturePackagingProperty().isNull());

		BooleanBinding isEmptyFileOrPassword = model.pkcsFileProperty().isNull().or(model.passwordProperty().isEmpty());

		BooleanBinding isPKCSIncomplete = model.tokenTypeProperty().isEqualTo(SignatureTokenType.PKCS11)
				.or(model.tokenTypeProperty().isEqualTo(SignatureTokenType.PKCS12)).and(isEmptyFileOrPassword);

		final BooleanBinding disableSignButton = isMandatoryFieldsEmpty.or(isASiCorPackagingPresent).or(isPKCSIncomplete);

		signButton.disableProperty().bind(disableSignButton);

		signButton.setOnAction(new EventHandler<ActionEvent>() {
			@Override
			public void handle(ActionEvent event) {
				progressSign.setDisable(false);

				final Service<DSSDocument> service = new Service<DSSDocument>() {
					@Override
					protected Task<DSSDocument> createTask() {
						return new SigningTask(signatureService, model);
					}
				};
				service.setOnSucceeded(new EventHandler<WorkerStateEvent>() {
					@Override
					public void handle(WorkerStateEvent event) {
						save(service.getValue());
						signButton.disableProperty().bind(disableSignButton);
						model.setPassword(null);
					}
				});
				service.setOnFailed(new EventHandler<WorkerStateEvent>() {
					@Override
					public void handle(WorkerStateEvent event) {
						Alert alert = new Alert(AlertType.ERROR, "Oops an error occurred : " + service.getMessage(), ButtonType.CLOSE);
						alert.showAndWait();
						signButton.disableProperty().bind(disableSignButton);
						model.setPassword(null);
					}
				});

				progressSign.progressProperty().bind(service.progressProperty());
				signButton.disableProperty().bind(service.runningProperty());
				service.start();
			}
		});
	}

	protected void updateSignatureFormForASiC(ASiCContainerType newValue) {
		model.setAsicContainerType(newValue);

		reinitSignatureFormats();
		reinitSignaturePackagings();

		if (newValue != null) { // ASiC
			cadesRadio.setDisable(false);
			xadesRadio.setDisable(false);
			hSignaturePackaging.setVisible(false);
		} else {
			cadesRadio.setDisable(false);
			padesRadio.setDisable(false);
			xadesRadio.setDisable(false);
			hSignaturePackaging.setVisible(true);
		}

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
			default:
				break;
			}
		}
	}

	private void reinitSignatureFormats() {
		cadesRadio.setDisable(true);
		padesRadio.setDisable(true);
		xadesRadio.setDisable(true);

		cadesRadio.setSelected(false);
		padesRadio.setSelected(false);
		xadesRadio.setSelected(false);
	}

	private void reinitSignaturePackagings() {
		envelopingRadio.setDisable(true);
		envelopedRadio.setDisable(true);
		detachedRadio.setDisable(true);

		envelopingRadio.setSelected(false);
		envelopedRadio.setSelected(false);
		detachedRadio.setSelected(false);
	}

	private void save(DSSDocument signedDocument) {
		FileChooser fileChooser = new FileChooser();
		fileChooser.setInitialFileName(signedDocument.getName());
		MimeType mimeType = signedDocument.getMimeType();
		ExtensionFilter extFilter = new ExtensionFilter(mimeType.getMimeTypeString(), "*." + MimeType.getExtension(mimeType));
		fileChooser.getExtensionFilters().add(extFilter);
		File fileToSave = fileChooser.showSaveDialog(stage);

		if (fileToSave != null) {
			try {
				FileOutputStream fos = new FileOutputStream(fileToSave);
				Utils.copy(signedDocument.openStream(), fos);
				Utils.closeQuietly(fos);
			} catch (Exception e) {
				Alert alert = new Alert(AlertType.ERROR, "Unable to save file : " + e.getMessage(), ButtonType.CLOSE);
				alert.showAndWait();
				return;
			}
		}
	}

}
