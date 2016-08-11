package eu.europa.esig.dss.web.service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.bind.DatatypeConverter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.Policy;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.asic.ASiCSignatureParameters;
import eu.europa.esig.dss.asic.signature.ASiCService;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.web.WebAppUtils;
import eu.europa.esig.dss.web.model.ExtensionForm;
import eu.europa.esig.dss.web.model.NexuSignatureDocumentForm;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

@Component
public class SigningService {

	private static final Logger logger = LoggerFactory.getLogger(SigningService.class);

	@Autowired
	private CAdESService cadesService;

	@Autowired
	private PAdESService padesService;

	@Autowired
	private XAdESService xadesService;

	@Autowired
	private ASiCService asicService;

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public DSSDocument extend(ExtensionForm extensionForm) {

		SignatureForm signatureForm = extensionForm.getSignatureForm();
		SignatureForm asicUnderlyingForm = extensionForm.getAsicUnderlyingForm();

		DSSDocument signedDocument = WebAppUtils.toDSSDocument(extensionForm.getSignedFile());
		DSSDocument originalDocument = WebAppUtils.toDSSDocument(extensionForm.getOriginalFile());

		DocumentSignatureService service = getSignatureService(signatureForm);

		AbstractSignatureParameters parameters = getSignatureParameters(signatureForm, asicUnderlyingForm);
		parameters.setSignatureLevel(extensionForm.getSignatureLevel());

		if (originalDocument != null) {
			parameters.setDetachedContent(originalDocument);
		}

		DSSDocument extendedDoc = service.extendDocument(signedDocument, parameters);
		return extendedDoc;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public ToBeSigned getDataToSign(NexuSignatureDocumentForm form) {
		logger.info("Start getDataToSign");
		DocumentSignatureService service = getSignatureService(form.getSignatureForm());

		AbstractSignatureParameters parameters = fillParameters(form);

		ToBeSigned toBeSigned = null;
		try {
			DSSDocument toSignDocument = WebAppUtils.toDSSDocument(form.getDocumentToSign());
			toBeSigned = service.getDataToSign(toSignDocument, parameters);
		} catch (Exception e) {
			logger.error("Unable to execute getDataToSign : " + e.getMessage(), e);
		}
		logger.info("End getDataToSign");
		return toBeSigned;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public DSSDocument signDocument(NexuSignatureDocumentForm form) {
		logger.info("Start signDocument");
		DocumentSignatureService service = getSignatureService(form.getSignatureForm());

		AbstractSignatureParameters parameters = fillParameters(form);

		DSSDocument signedDocument = null;
		try {
			DSSDocument toSignDocument = WebAppUtils.toDSSDocument(form.getDocumentToSign());
			SignatureAlgorithm sigAlgorithm = SignatureAlgorithm.getAlgorithm(form.getEncryptionAlgorithm(), form.getDigestAlgorithm());
			SignatureValue signatureValue = new SignatureValue(sigAlgorithm, DatatypeConverter.parseBase64Binary(form.getBase64SignatureValue()));
			signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
		} catch (Exception e) {
			logger.error("Unable to execute signDocument : " + e.getMessage(), e);
		}
		logger.info("End signDocument");
		return signedDocument;
	}

	private AbstractSignatureParameters fillParameters(NexuSignatureDocumentForm form) {
		AbstractSignatureParameters parameters = getSignatureParameters(form.getSignatureForm(), form.getAsicUnderlyingForm());
		parameters.setSignaturePackaging(form.getSignaturePackaging());
		parameters.setSignatureLevel(form.getSignatureLevel());
		parameters.setDigestAlgorithm(form.getDigestAlgorithm());
		// parameters.setEncryptionAlgorithm(form.getEncryptionAlgorithm()); retrieved from certificate
		parameters.bLevel().setSigningDate(form.getSigningDate());

		if (Utils.isStringNotEmpty(form.getPolicyOid()) && Utils.isStringNotEmpty(form.getPolicyBase64HashValue())
				&& (form.getPolicyDigestAlgorithm() != null)) {
			Policy signaturePolicy = new Policy();
			signaturePolicy.setId(form.getPolicyOid());
			signaturePolicy.setDigestAlgorithm(form.getPolicyDigestAlgorithm());
			signaturePolicy.setDigestValue(Utils.fromBase64(form.getPolicyBase64HashValue()));
			parameters.bLevel().setSignaturePolicy(signaturePolicy);
		}

		parameters.setSignWithExpiredCertificate(form.isSignWithExpiredCertificate());

		CertificateToken signingCertificate = DSSUtils.loadCertificateFromBase64EncodedString(form.getBase64Certificate());
		parameters.setSigningCertificate(signingCertificate);
		parameters.setEncryptionAlgorithm(signingCertificate.getEncryptionAlgorithm());

		List<String> base64CertificateChain = form.getBase64CertificateChain();
		if (Utils.isCollectionNotEmpty(base64CertificateChain)) {
			Set<CertificateToken> certificateChain = new HashSet<CertificateToken>();
			for (String base64Certificate : base64CertificateChain) {
				certificateChain.add(DSSUtils.loadCertificateFromBase64EncodedString(base64Certificate));
			}
			parameters.setCertificateChain(certificateChain);
		}

		return parameters;
	}

	@SuppressWarnings("rawtypes")
	private DocumentSignatureService getSignatureService(SignatureForm signatureForm) {
		DocumentSignatureService service = null;
		switch (signatureForm) {
		case CAdES:
			service = cadesService;
			break;
		case PAdES:
			service = padesService;
			break;
		case XAdES:
			service = xadesService;
			break;
		case ASiC_S:
		case ASiC_E:
			service = asicService;
			break;
		default:
			logger.error("Unknow signature form : " + signatureForm);
		}
		return service;
	}

	private AbstractSignatureParameters getSignatureParameters(SignatureForm signatureForm, SignatureForm underlyingForm) {
		AbstractSignatureParameters parameters = null;
		switch (signatureForm) {
		case CAdES:
			parameters = new CAdESSignatureParameters();
			break;
		case PAdES:
			PAdESSignatureParameters padesParams = new PAdESSignatureParameters();
			padesParams.setSignatureSize(9472 * 2); // double reserved space for signature
			parameters = padesParams;
			break;
		case XAdES:
			parameters = new XAdESSignatureParameters();
			break;
		case ASiC_S:
		case ASiC_E:
			ASiCSignatureParameters asicParameters = new ASiCSignatureParameters();
			if (underlyingForm != null) {
				asicParameters.aSiC().setUnderlyingForm(underlyingForm);
			}
			parameters = asicParameters;
			break;
		default:
			logger.error("Unknow signature form : " + signatureForm);
		}
		return parameters;
	}

}
