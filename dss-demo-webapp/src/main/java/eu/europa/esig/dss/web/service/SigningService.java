package eu.europa.esig.dss.web.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.asic.ASiCSignatureParameters;
import eu.europa.esig.dss.asic.signature.ASiCService;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.SignaturePackaging;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.x509.SignatureForm;
import eu.europa.esig.dss.x509.tsp.TSPSource;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

@Component
public class SigningService {

	private static final Logger logger = LoggerFactory.getLogger(SigningService.class);

	@Autowired
	private TSPSource tspSource;

	@Autowired
	private DataLoader dataLoader;

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public DSSDocument extend(SignatureForm signatureForm, SignaturePackaging packaging, SignatureLevel level, DSSDocument signedDocument,
			DSSDocument originalDocument) {

		DocumentSignatureService service = getSignatureService(signatureForm);
		service.setTspSource(tspSource);

		AbstractSignatureParameters parameters = getSignatureParameters(signatureForm);
		parameters.setSignaturePackaging(packaging);
		parameters.setSignatureLevel(level);

		if (originalDocument != null) {
			parameters.setDetachedContent(originalDocument);
		}

		DSSDocument extendedDoc = service.extendDocument(signedDocument, parameters);
		return extendedDoc;
	}

	@SuppressWarnings("rawtypes")
	private DocumentSignatureService getSignatureService(SignatureForm signatureForm) {
		DocumentSignatureService service = null;
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(dataLoader);
		switch (signatureForm) {
		case CAdES:
			service = new CAdESService(certificateVerifier);
			break;
		case PAdES:
			service = new PAdESService(certificateVerifier);
			break;
		case XAdES:
			service = new XAdESService(certificateVerifier);
			break;
		case ASiC_S:
		case ASiC_E:
			service = new ASiCService(certificateVerifier);
			break;
		default:
			logger.error("Unknow signature form : " + signatureForm);
		}
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
