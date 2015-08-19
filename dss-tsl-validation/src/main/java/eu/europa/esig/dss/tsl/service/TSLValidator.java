package eu.europa.esig.dss.tsl.service;

import java.util.List;
import java.util.concurrent.Callable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.XPathQueryHolder;
import eu.europa.esig.dss.tsl.TSLValidationModel;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.report.Reports;
import eu.europa.esig.dss.validation.report.SimpleReport;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;

public class TSLValidator implements Callable<TSLValidationModel>{

	private static final Logger logger = LoggerFactory.getLogger(TSLValidator.class);

	private TSLValidationModel validationModel;
	private KeyStoreCertificateSource dssKeyStore;
	private List<CertificateToken> potentialSigners;

	public TSLValidator(TSLValidationModel validationModel, KeyStoreCertificateSource dssKeyStore, List<CertificateToken> potentialSigners) {
		this.validationModel = validationModel;
		this.dssKeyStore = dssKeyStore;
		this.potentialSigners = potentialSigners;
	}

	@Override
	public TSLValidationModel call() throws Exception {
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier(true);
		certificateVerifier.setTrustedCertSource(buildTrustedCertificateSource(dssKeyStore, potentialSigners));

		DSSDocument dssDocument = new FileDocument(validationModel.getFilepath());
		XMLDocumentValidator xmlDocumentValidator = new XMLDocumentValidator(dssDocument);
		xmlDocumentValidator.setCertificateVerifier(certificateVerifier);
		// To increase the security: the default {@code XPathQueryHolder} is used.
		List<XPathQueryHolder> xPathQueryHolders = xmlDocumentValidator.getXPathQueryHolder();
		xPathQueryHolders.clear();
		xPathQueryHolders.add(new XPathQueryHolder());

		Reports reports = xmlDocumentValidator.validateDocument();
		SimpleReport simpleReport = reports.getSimpleReport();
		String indication = simpleReport.getIndication(simpleReport.getFirstSignatureId());
		boolean isValid = Indication.VALID.equals(indication);

		if (!isValid) {
			logger.info("The TSL signature validity details : \n" + simpleReport.toString());
		}

		return validationModel;
	}

	private CommonTrustedCertificateSource buildTrustedCertificateSource(KeyStoreCertificateSource dssKeyStore, List<CertificateToken> potentialSigners) {
		CommonTrustedCertificateSource commonTrustedCertificateSource = new CommonTrustedCertificateSource();
		for (CertificateToken potentialSigner : potentialSigners) {
			commonTrustedCertificateSource.addCertificate(potentialSigner);
		}
		List<CertificateToken> trustedCertificatesFromKeyStore = dssKeyStore.getCertificatesFromKeyStore();
		for (CertificateToken certificateToken : trustedCertificatesFromKeyStore) {
			commonTrustedCertificateSource.addCertificate(certificateToken);
		}
		return commonTrustedCertificateSource;
	}

}
