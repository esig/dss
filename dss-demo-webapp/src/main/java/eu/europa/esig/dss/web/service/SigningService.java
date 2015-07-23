package eu.europa.esig.dss.web.service;

import javax.xml.bind.DatatypeConverter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.asic.ASiCSignatureParameters;
import eu.europa.esig.dss.asic.signature.ASiCService;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.web.model.SignatureDocumentForm;
import eu.europa.esig.dss.x509.tsp.TSPSource;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

@Component
public class SigningService {

	private static final Logger logger = LoggerFactory.getLogger(SigningService.class);

	@Autowired
	private TSPSource tspSource;

	@SuppressWarnings({
		"rawtypes", "unchecked"
	})
	public DSSDocument extend(SignatureForm signatureForm, SignaturePackaging packaging, SignatureLevel level, DSSDocument signedDocument, DSSDocument originalDocument) {

		DocumentSignatureService service = getSignatureService(signatureForm);

		AbstractSignatureParameters parameters = getSignatureParameters(signatureForm);
		parameters.setSignaturePackaging(packaging);
		parameters.setSignatureLevel(level);

		if (originalDocument != null) {
			parameters.setDetachedContent(originalDocument);
		}

		DSSDocument extendedDoc = service.extendDocument(signedDocument, parameters);
		return extendedDoc;
	}

	public ToBeSigned getDataToSign(SignatureDocumentForm form) {
		logger.info("Start getDataToSign");
		DocumentSignatureService service = getSignatureService(form.getSignatureForm());

		AbstractSignatureParameters parameters = fillParameters(form);

		ToBeSigned toBeSigned = null;
		try {
			DSSDocument toSignDocument = new InMemoryDocument(form.getDocumentToSign().getBytes(), form.getDocumentToSign().getName());
			toBeSigned = service.getDataToSign(toSignDocument, parameters);
		} catch (Exception e) {
			logger.error("Unable to execute getDataToSign : " + e.getMessage(), e);
		}
		logger.info("End getDataToSign");
		return toBeSigned;
	}

	public DSSDocument signDocument(SignatureDocumentForm form) {
		logger.info("Start signDocument");
		DocumentSignatureService service = getSignatureService(form.getSignatureForm());

		AbstractSignatureParameters parameters = fillParameters(form);

		DSSDocument signedDocument = null;
		try {
			DSSDocument toSignDocument = new InMemoryDocument(form.getDocumentToSign().getBytes(), form.getDocumentToSign().getName());
			SignatureAlgorithm sigAlgorithm = SignatureAlgorithm.getAlgorithm(form.getEncryptionAlgorithm(), form.getDigestAlgorithm());
			SignatureValue signatureValue = new SignatureValue(sigAlgorithm, DatatypeConverter.parseBase64Binary(form.getBase64SignatureValue()));
			signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
		} catch (Exception e) {
			logger.error("Unable to execute signDocument : " + e.getMessage(), e);
		}
		logger.info("End signDocument");
		return signedDocument;
	}

	private AbstractSignatureParameters fillParameters(SignatureDocumentForm form) {
		AbstractSignatureParameters parameters = getSignatureParameters(form.getSignatureForm());
		parameters.setSignaturePackaging(form.getSignaturePackaging());
		parameters.setSignatureLevel(form.getSignatureLevel());
		parameters.setDigestAlgorithm(form.getDigestAlgorithm());
		parameters.bLevel().setSigningDate(form.getSigningDate());
		parameters.setSigningCertificate(DSSUtils.loadCertificateFromBase64EncodedString(form.getBase64Certificate()));
		return parameters;
	}

	@SuppressWarnings("rawtypes")
	private DocumentSignatureService getSignatureService(SignatureForm signatureForm) {
		DocumentSignatureService service = null;
		switch (signatureForm) {
			case CAdES:
				service = new CAdESService(new CommonCertificateVerifier());
				break;
			case PAdES:
				service = new PAdESService(new CommonCertificateVerifier());
				break;
			case XAdES:
				service = new XAdESService(new CommonCertificateVerifier());
				break;
			case ASiC_S:
			case ASiC_E:
				service = new ASiCService(new CommonCertificateVerifier());
				break;
			default:
				throw new DSSException("Unknow signature form : " + signatureForm);
		}
		service.setTspSource(tspSource);
		return service;
	}

	private AbstractSignatureParameters getSignatureParameters(SignatureForm signatureForm) {
		AbstractSignatureParameters parameters = null;
		switch (signatureForm) {
			case CAdES:
				parameters = new CAdESSignatureParameters();
				break;
			case PAdES:
				parameters = new PAdESSignatureParameters();
				break;
			case XAdES:
				parameters = new XAdESSignatureParameters();
				break;
			case ASiC_S:
			case ASiC_E:
				parameters = new ASiCSignatureParameters();
				break;
			default:
				logger.error("Unknow signature form : " + signatureForm);
		}
		return parameters;
	}

}
