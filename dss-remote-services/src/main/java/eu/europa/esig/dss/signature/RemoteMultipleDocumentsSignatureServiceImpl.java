package eu.europa.esig.dss.signature;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.ASiCContainerType;
import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.RemoteSignatureParameters;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.asic.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class RemoteMultipleDocumentsSignatureServiceImpl extends AbstractRemoteSignatureServiceImpl
		implements RemoteMultipleDocumentsSignatureService<RemoteDocument, RemoteSignatureParameters> {

	private static final Logger logger = LoggerFactory.getLogger(RemoteMultipleDocumentsSignatureServiceImpl.class);

	private MultipleDocumentsSignatureService<XAdESSignatureParameters> xadesService;

	private MultipleDocumentsSignatureService<ASiCWithCAdESSignatureParameters> asicWithCAdESService;

	private MultipleDocumentsSignatureService<ASiCWithXAdESSignatureParameters> asicWithXAdESService;

	public void setXadesService(MultipleDocumentsSignatureService<XAdESSignatureParameters> xadesService) {
		this.xadesService = xadesService;
	}

	public void setAsicWithCAdESService(MultipleDocumentsSignatureService<ASiCWithCAdESSignatureParameters> asicWithCAdESService) {
		this.asicWithCAdESService = asicWithCAdESService;
	}

	public void setAsicWithXAdESService(MultipleDocumentsSignatureService<ASiCWithXAdESSignatureParameters> asicWithXAdESService) {
		this.asicWithXAdESService = asicWithXAdESService;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public ToBeSigned getDataToSign(List<RemoteDocument> toSignDocuments, RemoteSignatureParameters remoteParameters) throws DSSException {
		logger.info("GetDataToSign in process...");
		AbstractSignatureParameters parameters = createParameters(remoteParameters);
		MultipleDocumentsSignatureService service = getServiceForSignature(remoteParameters);
		List<DSSDocument> dssDocuments = createDSSDocuments(toSignDocuments);
		ToBeSigned dataToSign = service.getDataToSign(dssDocuments, parameters);
		logger.info("GetDataToSign is finished");
		return dataToSign;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public DSSDocument signDocument(List<RemoteDocument> toSignDocuments, RemoteSignatureParameters remoteParameters, SignatureValue signatureValue)
			throws DSSException {
		logger.info("SignDocument in process...");
		AbstractSignatureParameters parameters = createParameters(remoteParameters);
		MultipleDocumentsSignatureService service = getServiceForSignature(remoteParameters);
		List<DSSDocument> dssDocuments = createDSSDocuments(toSignDocuments);
		DSSDocument signDocument = service.signDocument(dssDocuments, parameters, signatureValue);
		logger.info("SignDocument is finished");
		return signDocument;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public DSSDocument extendDocument(RemoteDocument toExtendDocument, RemoteSignatureParameters remoteParameters) throws DSSException {
		logger.info("ExtendDocument in process...");
		AbstractSignatureParameters parameters = createParameters(remoteParameters);
		MultipleDocumentsSignatureService service = getServiceForSignature(remoteParameters);
		DSSDocument dssDocument = createDSSDocument(toExtendDocument);
		DSSDocument extendDocument = service.extendDocument(dssDocument, parameters);
		logger.info("ExtendDocument is finished");
		return extendDocument;
	}

	@SuppressWarnings("rawtypes")
	private MultipleDocumentsSignatureService getServiceForSignature(RemoteSignatureParameters parameters) {
		ASiCContainerType asicContainerType = parameters.getAsicContainerType();
		SignatureLevel signatureLevel = parameters.getSignatureLevel();
		SignatureForm signatureForm = signatureLevel.getSignatureForm();
		if (asicContainerType != null) {
			switch (signatureForm) {
			case XAdES:
				return asicWithXAdESService;
			case CAdES:
				return asicWithCAdESService;
			default:
				throw new DSSException("Unrecognized format (XAdES or CAdES are allowed with ASiC) : " + signatureForm);
			}
		} else {
			if (SignatureForm.XAdES == signatureForm) {
				return xadesService;
			} else {
				throw new DSSException("Unrecognized format (XAdES or CAdES are allowed with ASiC or XAdES) : " + signatureForm);
			}
		}
	}

}
