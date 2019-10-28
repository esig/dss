package eu.europa.esig.dss.xades.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedRevocation;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.definition.XPathExpressionBuilder;
import eu.europa.esig.dss.xades.definition.xades141.XAdES141Element;

/**
 * See DSS-1806
 */
public class XAdESCrossCertificationDoubleLTATest extends PKIFactoryAccess {

	@Test
	public void test() throws Exception {
		
		DSSDocument documentToSign = new FileDocument("src/test/resources/sample.xml");

        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        
        CertificateToken crossCertificate = getCertificateByPrimaryKey("external-ca", 2002);
        CommonCertificateSource trustedListsCertificateSource = new CommonCertificateSource();
        trustedListsCertificateSource.addCertificate(crossCertificate);
        trustedListsCertificateSource.addCertificate(getCertificate(ROOT_CA));
        
        CommonTrustedCertificateSource commonTrustedCertificateSource = new CommonTrustedCertificateSource();
        commonTrustedCertificateSource.importAsTrusted(trustedListsCertificateSource);
        
        CertificateVerifier customCertificateVerifier = getCompleteCertificateVerifier();
        customCertificateVerifier.getTrustedCertSources().clear();
        customCertificateVerifier.setTrustedCertSource(commonTrustedCertificateSource);
		
        XAdESService service = new XAdESService(customCertificateVerifier);
        service.setTspSource(getGoodTsa());

        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
        
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
        validator.setCertificateVerifier(customCertificateVerifier);
        validator.setDetachedContents(Arrays.asList(documentToSign));
        Reports reports = validator.validateDocument();
        // reports.print();
        
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        
        // check no duplicate revocations for a certificate
        List<CertificateWrapper> usedCertificates = diagnosticData.getUsedCertificates();
        for (CertificateWrapper certificateWrapper : usedCertificates) {
        	List<CertificateRevocationWrapper> certificateRevocationData = certificateWrapper.getCertificateRevocationData();
        	List<String> revocationIds = new ArrayList<String>();
        	for (CertificateRevocationWrapper revocationWrapper : certificateRevocationData) {
        		assertTrue(!revocationIds.contains(revocationWrapper.getId()));
        		revocationIds.add(revocationWrapper.getId());
        	}
        	assertEquals(certificateRevocationData.size(), revocationIds.size());
        }
        assertEquals(7, usedCertificates.size());
        
        List<XmlRelatedCertificate> relatedCertificatesFirstLTA = signature.getRelatedCertificates();
        List<XmlRelatedRevocation> relatedRevocationsFirstLTA = signature.getRelatedRevocations();

        service = new XAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
        
        XAdESSignatureParameters extendParameters = new XAdESSignatureParameters();
        extendParameters.setDetachedContents(Arrays.asList(documentToSign));
        extendParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
        DSSDocument doubleLTADoc = service.extendDocument(signedDocument, extendParameters);
        // doubleLTADoc.save("target/doubleLTA.xml");
        
        validator = SignedDocumentValidator.fromDocument(doubleLTADoc);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        validator.setDetachedContents(Arrays.asList(documentToSign));
        reports = validator.validateDocument();
        // reports.print();
        
        diagnosticData = reports.getDiagnosticData();
        signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        
        List<XmlRelatedCertificate> relatedCertificatesSecondLTA = signature.getRelatedCertificates();
        List<XmlRelatedRevocation> relatedRevocationsSecondLTA = signature.getRelatedRevocations();
        
        assertEquals(relatedCertificatesFirstLTA.size(), relatedCertificatesSecondLTA.size());
        assertEquals(relatedRevocationsFirstLTA.size(), relatedRevocationsSecondLTA.size());
        
        Collection<XmlRelatedCertificate> tstValidationDataCerts = signature.getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA);
        assertTrue(Utils.isCollectionEmpty(tstValidationDataCerts));
        
        Collection<XmlRelatedRevocation> tstValidationDataRevocations = signature.getRelatedRevocationsByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA);
        assertTrue(Utils.isCollectionEmpty(tstValidationDataRevocations));
        
        Document document = DomUtils.buildDOM(doubleLTADoc);
        assertNotNull(document);
        
        Element timeStampValidationDataElement = DomUtils.getElement(document, 
        		new XPathExpressionBuilder().all().element(XAdES141Element.TIMESTAMP_VALIDATION_DATA).build());
        assertNull(timeStampValidationDataElement);
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER_CROSS_CERTIF;
	}

}
