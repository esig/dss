package eu.europa.esig.dss.asic.signature.asice;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.Before;

import eu.europa.esig.dss.ASiCContainerType;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.asic.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScope;
import eu.europa.esig.dss.signature.AbstractPkiFactoryTestMultipleDocumentsSignatureService;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class ASiCSCAdESLevelBMultiFilesWithoutNameTest extends AbstractPkiFactoryTestMultipleDocumentsSignatureService<ASiCWithCAdESSignatureParameters> {

	private ASiCWithCAdESService service;
	private ASiCWithCAdESSignatureParameters signatureParameters;
	private List<DSSDocument> documentToSigns = new ArrayList<DSSDocument>();
	
	@Before
	public void init() throws Exception {
		service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		documentToSigns.add(new InMemoryDocument("Hello World !".getBytes()));
		documentToSigns.add(new InMemoryDocument("Bye World !".getBytes()));

		signatureParameters = new ASiCWithCAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
		
	}

	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		assertEquals(1, Utils.collectionSize(signatureScopes)); // package.zip
	}

	@Override
	protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected MimeType getExpectedMime() {
		return MimeType.ASICS;
	}

	@Override
	protected boolean isBaselineT() {
		return false;
	}

	@Override
	protected boolean isBaselineLTA() {
		return false;
	}

	@Override
	protected List<DSSDocument> getDocumentsToSign() {
		return documentToSigns;
	}

	@Override
	protected MultipleDocumentsSignatureService<ASiCWithCAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
