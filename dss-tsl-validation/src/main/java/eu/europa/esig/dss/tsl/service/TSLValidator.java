package eu.europa.esig.dss.tsl.service;

import java.io.File;
import java.util.List;
import java.util.concurrent.Callable;

import org.apache.commons.collections.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.XPathQueryHolder;
import eu.europa.esig.dss.tsl.TSLValidationResult;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.report.Reports;
import eu.europa.esig.dss.validation.report.SimpleReport;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;

public class TSLValidator implements Callable<TSLValidationResult> {

	private static final Logger logger = LoggerFactory.getLogger(TSLValidator.class);

	private File file;
	private String countryCode;
	private KeyStoreCertificateSource dssKeyStore;
	private List<CertificateToken> potentialSigners;

	/**
	 * Constructor used to instantiate a validator for a LOTL
	 *
	 * @param file
	 *            the file to validate (a LOTL file)
	 * @param countryCode
	 *            the country code
	 * @param dssKeyStore
	 *            the key store which contains trusted certificates (allowed to sign the LOTL)
	 */
	public TSLValidator(File file, String countryCode, KeyStoreCertificateSource dssKeyStore) {
		this.file = file;
		this.countryCode = countryCode;
		this.dssKeyStore = dssKeyStore;
	}

	/**
	 * Constructor used to instantiate a validator for a TSL
	 *
	 * @param file
	 *            the file to validate (a TSL file (not LOTL)
	 * @param countryCode
	 *            the country code
	 * @param dssKeyStore
	 *            the key store which contains trusted certificates (allowed to sign the LOTL)
	 * @param potentialSigners
	 *            the list of certificates allowed to sign this TSL
	 */
	public TSLValidator(File file, String countryCode, KeyStoreCertificateSource dssKeyStore, List<CertificateToken> potentialSigners) {
		this.file = file;
		this.countryCode = countryCode;
		this.dssKeyStore = dssKeyStore;
		this.potentialSigners = potentialSigners;
	}

	@Override
	public TSLValidationResult call() throws Exception {
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier(true);
		certificateVerifier.setTrustedCertSource(buildTrustedCertificateSource(dssKeyStore, potentialSigners));

		DSSDocument dssDocument = new FileDocument(file);
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

		TSLValidationResult result = new TSLValidationResult();
		result.setCountryCode(countryCode);
		result.setIndication(indication);
		result.setSubIndication(simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		if (!isValid) {
			logger.info("The TSL signature is not valid : \n" + simpleReport.toString());
		}

		return result;
	}

	private CommonTrustedCertificateSource buildTrustedCertificateSource(KeyStoreCertificateSource dssKeyStore, List<CertificateToken> potentialSigners) {
		CommonTrustedCertificateSource commonTrustedCertificateSource = new CommonTrustedCertificateSource();
		if (CollectionUtils.isNotEmpty(potentialSigners)) {
			for (CertificateToken potentialSigner : potentialSigners) {
				commonTrustedCertificateSource.addCertificate(potentialSigner);
			}
		}
		if ((dssKeyStore != null) && CollectionUtils.isNotEmpty(dssKeyStore.getCertificatesFromKeyStore())) {
			List<CertificateToken> trustedCertificatesFromKeyStore = dssKeyStore.getCertificatesFromKeyStore();
			for (CertificateToken certificateToken : trustedCertificatesFromKeyStore) {
				commonTrustedCertificateSource.addCertificate(certificateToken);
			}
		}
		return commonTrustedCertificateSource;
	}

}
