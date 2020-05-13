package eu.europa.esig.dss.pades.extension;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

@RunWith(Parameterized.class)
public class PAdESDSS2058 extends PKIFactoryAccess {

	// Run 10 times this test
	private static final int times = 10;
	
	private DSSDocument dssDocument;
	
	@Parameters(name = "Test {index} : {0}")
	public static List<Object[]> data() {
	    Object[] arr = { new InMemoryDocument(PAdESDSS2058.class.getResourceAsStream("/validation/dss-2058/dss-2058-LTA-test.pdf"), "dss-2058-LTA-test.pdf"),
	    		new InMemoryDocument(PAdESDSS2058.class.getResourceAsStream("/validation/dss-2058/dss-2058-QC-LTA-test.pdf"), "dss-2058-QC-LTA-test.pdf")};
	    List<Object[]> list = new ArrayList<Object[]>();
		for (int i = 0; i < arr.length; i++) {
			for (int j = 0; j < times; j++) {
				Object[] array = {arr[i], j};
				list.add(array);
			}
		}
	    return list;
	}

	public PAdESDSS2058(DSSDocument dssDocument, int i) {
		this.dssDocument = dssDocument;
	}

	@Test
	public void test() throws Exception {
		CertificateVerifier completeCertificateVerifier = getCompleteCertificateVerifier();
		completeCertificateVerifier.setCheckRevocationForUntrustedChains(true);
		completeCertificateVerifier.setExceptionOnMissingRevocationData(false);
		completeCertificateVerifier.setExceptionOnRevokedCertificate(false);

		PAdESService service = new PAdESService(completeCertificateVerifier);
		service.setTspSource(getCompositeTsa());
		
		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		
		DSSDocument extendedDocument = service.extendDocument(dssDocument, signatureParameters);
		
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(extendedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		for (CertificateWrapper certificateWrapper : diagnosticData.getUsedCertificates()) {
			if (certificateWrapper.isSelfSigned()) {
				continue;
			}
			for (CertificateRevocationWrapper certRevocationWrapper : certificateWrapper.getCertificateRevocationData()) {
				Date lastUseTime = null;
				Date poeTimeDate = null;
				for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
					for (CertificateWrapper certChainItem : timestampWrapper.getCertificateChain()) {
						if (certificateWrapper.equals(certChainItem) && (lastUseTime == null || timestampWrapper.getProductionTime().after(lastUseTime))) {
							lastUseTime = timestampWrapper.getProductionTime();
						}
					}
					if (timestampWrapper.getTimestampedRevocationIds().contains(certRevocationWrapper.getId()) && 
							(poeTimeDate == null || timestampWrapper.getProductionTime().before(poeTimeDate))) {
						poeTimeDate = timestampWrapper.getProductionTime();
					}
				}
				assertNotNull(poeTimeDate);
				if (lastUseTime != null) {
					assertTrue(certRevocationWrapper.getProductionDate().compareTo(lastUseTime) >= 0);
				} else {
					// signature cert chain
					assertTrue(certRevocationWrapper.getProductionDate().compareTo(poeTimeDate) <= 0);
				}
			}
		}
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
