/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.ObjectIdentifier;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.OfflineRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.test.signature.AbstractPkiFactoryTestDocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.dataobject.DSSDataObjectFormat;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.validationreport.jaxb.SAMessageDigestType;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Attribute;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Path;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigElement;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractXAdESTestSignature extends AbstractPkiFactoryTestDocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> {

	@Override
	protected List<DSSDocument> getOriginalDocuments() {
		return Collections.singletonList(getDocumentToSign());
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);

		assertTrue(DomUtils.isDOM(byteArray));
		// Check for duplicate ids
		assertFalse(DSSXMLUtils.isDuplicateIdsDetected(new InMemoryDocument(byteArray)));

		Document documentDOM = DomUtils.buildDOM(byteArray);
		assertNotNull(documentDOM);
		checkDataObjectFormat(documentDOM);
	}

	protected void checkDataObjectFormat(Document documentDOM) {
		NodeList signatureNodeList = DSSXMLUtils.getAllSignaturesExceptCounterSignatures(documentDOM);
		for (int i = 0; i < signatureNodeList.getLength(); i++) {
			Element signatureElement = (Element) signatureNodeList.item(i);
			NodeList dataObjectFormatNodeList = DomUtils.getNodeList(signatureElement, new XAdES132Path().getDataObjectFormat());

			List<DSSDataObjectFormat> dataObjectFormatList = getSignatureParameters().getDataObjectFormatList();
			for (int j = 0; j < dataObjectFormatNodeList.getLength(); j++) {
				Element dataObjectFormat = (Element) dataObjectFormatNodeList.item(j);
				String objectReference = dataObjectFormat.getAttribute(XAdES132Attribute.OBJECT_REFERENCE.getAttributeName());
				assertNotNull(objectReference);

				Element elementById = DomUtils.getElementById(documentDOM, DomUtils.getId(objectReference));
				assertNotNull(elementById);
				assertTrue(XMLDSigElement.REFERENCE.isSameTagName(elementById.getLocalName()));

				Element mimeTypeElement = DomUtils.getElement(dataObjectFormat, new XAdES132Path().getCurrentMimeType());
				assertNotNull(mimeTypeElement);
				assertTrue(Utils.isStringNotEmpty(mimeTypeElement.getTextContent()));

				if (dataObjectFormatList != null) {
					DSSDataObjectFormat dssDOF = dataObjectFormatList.get(j);

					Element descriptionElement = DomUtils.getElement(dataObjectFormat, new XAdES132Path().getCurrentDescription());
					if (dssDOF.getDescription() != null) {
						assertNotNull(descriptionElement);
						assertEquals(dssDOF.getDescription(), descriptionElement.getTextContent());
					} else {
						assertNull(descriptionElement);
					}

					Element objectIdentifierElement = DomUtils.getElement(dataObjectFormat, new XAdES132Path().getCurrentObjectIdentifier());
					if (dssDOF.getObjectIdentifier() != null) {
						ObjectIdentifier oId = dssDOF.getObjectIdentifier();
						assertNotNull(objectIdentifierElement);
						checkObjectIdentifierType(oId, objectIdentifierElement);
					} else {
						assertNull(objectIdentifierElement);
					}

					mimeTypeElement = DomUtils.getElement(dataObjectFormat, new XAdES132Path().getCurrentMimeType());
					assertNotNull(mimeTypeElement);
					assertEquals(dssDOF.getMimeType(), mimeTypeElement.getTextContent());

					Element encodingElement = DomUtils.getElement(dataObjectFormat, new XAdES132Path().getCurrentEncoding());
					if (dssDOF.getEncoding() != null) {
						assertNotNull(encodingElement);
						assertEquals(dssDOF.getEncoding(), encodingElement.getTextContent());
					} else {
						assertNull(encodingElement);
					}
				}
			}
		}
	}

	protected void checkObjectIdentifierType(ObjectIdentifier objectIdentifier, Element objectIdentifierElement) {
		assertNotNull(objectIdentifier);
		if (Utils.isStringNotEmpty(objectIdentifier.getOid()) || Utils.isStringNotEmpty(objectIdentifier.getUri())) {
			Element identifier = DomUtils.getElement(objectIdentifierElement, new XAdES132Path().getCurrentIdentifier());
			assertNotNull(identifier);
			assertTrue(identifier.getTextContent().equals(objectIdentifier.getOid()) || identifier.getTextContent().equals(objectIdentifier.getUri()));
			if (objectIdentifier.getQualifier() != null) {
				String qualifier = identifier.getAttribute(XAdES132Attribute.QUALIFIER.getAttributeName());
				assertEquals(objectIdentifier.getQualifier().getValue(), qualifier);
			}
		}
		Element description = DomUtils.getElement(objectIdentifierElement, new XAdES132Path().getCurrentDescription());
		if (objectIdentifier.getDescription() != null) {
			assertNotNull(description);
			assertEquals(objectIdentifier.getDescription(), description.getTextContent());
		} else {
			assertNull(description);
		}
		NodeList docRefs = DomUtils.getNodeList(objectIdentifierElement, new XAdES132Path().getCurrentDocumentationReferenceElements());
		assertNotNull(docRefs);
		if (Utils.isArrayNotEmpty(objectIdentifier.getDocumentationReferences())) {
			assertNotEquals(0, docRefs.getLength());
			for (int i = 0; i < docRefs.getLength(); i++) {
				Node ref = docRefs.item(i);
				assertTrue(ref instanceof Element);
				assertEquals(objectIdentifier.getDocumentationReferences()[i], ref.getTextContent());
			}
		} else {
			assertNotNull(docRefs);
			assertEquals(0, docRefs.getLength());
		}
	}

	@Override
	protected MimeType getExpectedMime() {
		return MimeTypeEnum.XML;
	}

	@Override
	protected boolean isBaselineT() {
		SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
		return SignatureLevel.XAdES_BASELINE_LTA.equals(signatureLevel) || SignatureLevel.XAdES_BASELINE_LT.equals(signatureLevel)
				|| SignatureLevel.XAdES_BASELINE_T.equals(signatureLevel) || SignatureLevel.XAdES_T.equals(signatureLevel)
				|| SignatureLevel.XAdES_C.equals(signatureLevel) || SignatureLevel.XAdES_X.equals(signatureLevel)
				|| SignatureLevel.XAdES_XL.equals(signatureLevel) || SignatureLevel.XAdES_A.equals(signatureLevel);
	}

	@Override
	protected boolean isBaselineLTA() {
		SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
		return SignatureLevel.XAdES_BASELINE_LTA.equals(signatureLevel) || SignatureLevel.XAdES_A.equals(signatureLevel);
	}

	@Override
	protected void checkSignatureValue(DiagnosticData diagnosticData) {
		super.checkSignatureValue(diagnosticData);

		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			if (signatureWrapper.getEncryptionAlgorithm() != null && signatureWrapper.getDigestAlgorithm() != null &&
					signatureWrapper.getEncryptionAlgorithm().isEquivalent(EncryptionAlgorithm.ECDSA)) {
				assertFalse(DSSASN1Utils.isAsn1EncodedSignatureValue(signatureWrapper.getSignatureValue()), "PLAIN-ECDSA is expected!");
			}
		}
	}

	@Override
	protected void validateETSIMessageDigest(SAMessageDigestType md) {
		assertNull(md);
	}

	protected void verifySourcesAndDiagnosticDataWithOrphans(List<AdvancedSignature> signatures, DiagnosticData diagnosticData) {
		for (AdvancedSignature advancedSignature : signatures) {
			SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(advancedSignature.getId());

			SignatureCertificateSource certificateSource = advancedSignature.getCertificateSource();
			FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();

			// Tokens
			assertEquals(certificateSource.getKeyInfoCertificates().size(),
					foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.KEY_INFO).size());
			assertEquals(certificateSource.getCertificateValues().size(),
					foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
			assertEquals(certificateSource.getTimeStampValidationDataCertValues().size(),
					foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA).size());
			assertEquals(certificateSource.getAnyValidationDataCertValues().size(),
					foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.ANY_VALIDATION_DATA).size());
			assertEquals(certificateSource.getAttrAuthoritiesCertValues().size(),
					foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.ATTR_AUTHORITIES_CERT_VALUES).size());
			assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.SIGNED_DATA).size()
					+ foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.SIGNED_DATA).size());
			assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.DSS_DICTIONARY).size()
					+ foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.DSS_DICTIONARY).size());
			assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.VRI_DICTIONARY).size()
					+ foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.VRI_DICTIONARY).size());
			assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.BASIC_OCSP_RESP).size()
					+ foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.BASIC_OCSP_RESP).size());

			// Refs
			assertEquals(certificateSource.getSigningCertificateRefs().size(),
					foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
			assertEquals(0, foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS).size());
			assertEquals(certificateSource.getCompleteCertificateRefs().size(),
					foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).size()
							+ foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).size());

			List<TimestampToken> timestamps = advancedSignature.getAllTimestamps();
			for (TimestampToken timestampToken : timestamps) {
				TimestampWrapper timestampWrapper = diagnosticData.getTimestampById(timestampToken.getDSSIdAsString());

				certificateSource = timestampToken.getCertificateSource();
				foundCertificates = timestampWrapper.foundCertificates();

				// Tokens
				assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.KEY_INFO).size());
				assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
				assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA).size());
				assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.ATTR_AUTHORITIES_CERT_VALUES).size());
				assertEquals(certificateSource.getSignedDataCertificates().size(),
						foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.SIGNED_DATA).size());
				assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.DSS_DICTIONARY).size());
				assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.VRI_DICTIONARY).size());
				assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.BASIC_OCSP_RESP).size());

				// Refs
				assertEquals(certificateSource.getSigningCertificateRefs().size(),
						foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
				assertEquals(0, foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS).size());
				assertEquals(0, foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).size());
			}

			OfflineRevocationSource<OCSP> ocspSource = advancedSignature.getOCSPSource();
			Set<RevocationToken<OCSP>> allRevocationTokens = ocspSource.getAllRevocationTokens();
			for (RevocationToken<OCSP> revocationToken : allRevocationTokens) {
				RevocationCertificateSource revocationCertificateSource = revocationToken.getCertificateSource();
				if (revocationCertificateSource != null) {
					RevocationWrapper revocationWrapper = diagnosticData.getRevocationById(revocationToken.getDSSIdAsString());
					foundCertificates = revocationWrapper.foundCertificates();

					assertEquals(revocationCertificateSource.getCertificates().size(), foundCertificates.getRelatedCertificates().size());
					assertEquals(revocationCertificateSource.getAllCertificateRefs().size(), foundCertificates.getRelatedCertificateRefs().size());
				}
			}
		}
	}

	@Override
	protected boolean documentPresent(DSSDocument original, List<DSSDocument> retrievedDocuments) {
		boolean found = false;
		boolean toBeCanonicalized = MimeTypeEnum.XML.equals(original.getMimeType()) || MimeTypeEnum.HTML.equals(original.getMimeType());
		String originalDigest = getDigest(original, toBeCanonicalized);
		for (DSSDocument retrieved : retrievedDocuments) {
			String retrievedDigest = getDigest(retrieved, toBeCanonicalized);
			if (Utils.areStringsEqual(originalDigest, retrievedDigest)) {
				found = true;
				break;
			}
		}
		return found;
	}

	protected String getDigest(DSSDocument doc, boolean toBeCanonicalized) {
		byte[] byteArray = DSSUtils.toByteArray(doc);
		if (toBeCanonicalized && DomUtils.isDOM(doc)) {
			try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
				// we canonicalize to ignore the header (which is not covered by the signature)
				Canonicalizer c14n = Canonicalizer.getInstance(getCanonicalizationMethod());
				c14n.canonicalize(byteArray, baos, true);
				byteArray = baos.toByteArray();
			} catch (XMLSecurityException | IOException e) {
				// Not always able to canonicalize (more than one file can be covered (XML +
				// something else) )
			}
		}
		// LOG.info("Bytes : {}", new String(byteArray));
		return Utils.toBase64(DSSUtils.digest(DigestAlgorithm.SHA256, byteArray));
	}

	@Override
	protected boolean areSignedAssertionsEqual(String signedAssertionOne, String signedAssertionTwo) {
		Document expected = DomUtils.buildDOM(signedAssertionOne);
		Document extracted = DomUtils.buildDOM(signedAssertionTwo);
		return expected.isEqualNode(extracted);
	}

}
