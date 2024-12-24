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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerInfo;
import eu.europa.esig.dss.enumerations.ArchiveTimestampHashIndexVersion;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.test.signature.AbstractPkiFactoryTestDocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TimeStampToken;

import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.stream.Collectors;

import static eu.europa.esig.dss.spi.OID.id_aa_ATSHashIndexV3;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class AbstractCAdESTestSignature extends AbstractPkiFactoryTestDocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> {

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);
		checkSignedAttributesOrder(byteArray);
		checkSignaturePackaging(byteArray);
		checkArchiveTimeStampV3(byteArray);
	}

	@Override
	protected List<DSSDocument> getOriginalDocuments() {
		return Collections.singletonList(getDocumentToSign());
	}

	protected void checkSignedAttributesOrder(byte[] encoded) {
		try (ASN1InputStream asn1sInput = new ASN1InputStream(encoded)) {
			ASN1Sequence asn1Seq = (ASN1Sequence) asn1sInput.readObject();

			SignedData signedData = SignedData.getInstance(DERTaggedObject.getInstance(asn1Seq.getObjectAt(1)).getBaseObject());

			ASN1Set signerInfosAsn1 = signedData.getSignerInfos();
			SignerInfo signedInfo = SignerInfo.getInstance(ASN1Sequence.getInstance(signerInfosAsn1.getObjectAt(0)));

			ASN1Set authenticatedAttributeSet = signedInfo.getAuthenticatedAttributes();

			int previousSize = 0;
			for (int i = 0; i < authenticatedAttributeSet.size(); i++) {
				Attribute attribute = Attribute.getInstance(authenticatedAttributeSet.getObjectAt(i));
				ASN1ObjectIdentifier attrTypeOid = attribute.getAttrType();
				ASN1Set attrValues = attribute.getAttrValues();
				int size = attrTypeOid.getEncoded().length + attrValues.getEncoded().length;

				assertTrue(size >= previousSize);
				previousSize = size;
			}
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	protected void checkSignaturePackaging(byte[] byteArray) {
		try {
			CMSSignedData cmsSignedData = new CMSSignedData(byteArray);
			assertEquals(SignaturePackaging.DETACHED.equals(getSignatureParameters().getSignaturePackaging()),
					cmsSignedData.isDetachedSignature());
			assertEquals(SignaturePackaging.DETACHED.equals(getSignatureParameters().getSignaturePackaging()),
					cmsSignedData.getSignedContent() == null);

		} catch (CMSException e) {
			fail(e);
		}
	}
	
	@Override
	protected void checkSignatureInformationStore(DiagnosticData diagnosticData) {
		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			checkSignatureInformationStore(signature.getSignatureInformationStore());
		}
		for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
			checkSignatureInformationStore(timestamp.getSignatureInformationStore());
		}
	}
	
	protected void checkSignatureInformationStore(List<XmlSignerInfo> signatureInformationStore) {
		assertNotNull(signatureInformationStore);
		int verifiedNumber = 0;
		for (XmlSignerInfo signerInfo : signatureInformationStore) {
			if (Utils.isTrue(signerInfo.isCurrent())) {
				++verifiedNumber;
			}
		}
		assertEquals(1, verifiedNumber);
		
		assertEquals(1, signatureInformationStore.size());
	}

	protected void checkArchiveTimeStampV3(byte[] byteArray) {
		if (!isBaselineLTA()) {
			return; // skip
		}

		try {
			CMSSignedData cmsSignedData = new CMSSignedData(byteArray);
			for (SignerInformation signerInformation : cmsSignedData.getSignerInfos().getSigners()) {
				AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
				assertNotNull(unsignedAttributes);
				boolean arcTstV3Found = false;
				for (Attribute attribute : unsignedAttributes.toASN1Structure().getAttributes()) {
					if (OID.id_aa_ets_archiveTimestampV3.equals(attribute.getAttrType())) {
						TimeStampToken arcTstV3 = CMSUtils.getTimeStampToken(attribute);
						assertNotNull(arcTstV3);

						AttributeTable tstV3UnsignedAttributes = arcTstV3.getUnsignedAttributes();
						assertNotNull(tstV3UnsignedAttributes);

						ASN1ObjectIdentifier attrType = null;
						Attribute tstV3HashIndex = null;
						for (Attribute tstV3Attribute : tstV3UnsignedAttributes.toASN1Structure().getAttributes()) {
							if (id_aa_ATSHashIndexV3.equals(tstV3Attribute.getAttrType())) {
								attrType = tstV3Attribute.getAttrType();
								tstV3HashIndex = tstV3Attribute;
							}
						}
						assertNotNull(attrType);
						assertNotNull(tstV3HashIndex);

						final ASN1Set attrValues = tstV3HashIndex.getAttrValues();
						assertNotNull(attrValues);
						assertEquals(1, attrValues.size());
						ASN1Primitive asn1Primitive =  attrValues.getObjectAt(0).toASN1Primitive();
						ASN1Sequence atsHashIndexValue = assertInstanceOf(ASN1Sequence.class, asn1Primitive);

						AlgorithmIdentifier algorithmIdentifier = DSSASN1Utils.getAlgorithmIdentifier(atsHashIndexValue);
						assertNotNull(algorithmIdentifier);
						DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(algorithmIdentifier.getAlgorithm().getId());
						assertNotNull(digestAlgorithm);
						assertEquals(getSignatureParameters().getArchiveTimestampParameters().getDigestAlgorithm(), digestAlgorithm);

						ASN1Sequence certHashes = CMSUtils.getCertificatesHashIndex(atsHashIndexValue);
						List<DEROctetString> certHashesList = DSSASN1Utils.getDEROctetStrings(certHashes);

						Collection<X509CertificateHolder> certificates = cmsSignedData.getCertificates().getMatches(null);
						for (final X509CertificateHolder certificate : certificates) {
							byte[] digest = DSSUtils.digest(digestAlgorithm, certificate.getEncoded());
							final DEROctetString derOctetStringDigest = new DEROctetString(digest);
							if (certHashesList.remove(derOctetStringDigest)) {
								// good
							} else {
								fail("SignedData certificate is not present in timestamp!");
							}
						}
						if (!certHashesList.isEmpty()) {
							fail("Some certificates have not been found in SignedData.certificates!");
						}

						ASN1Sequence crlHashIndex = CMSUtils.getCRLHashIndex(atsHashIndexValue);
						List<DEROctetString> crlHashesList = DSSASN1Utils.getDEROctetStrings(crlHashIndex);

						final SignedData signedData = SignedData.getInstance(cmsSignedData.toASN1Structure().getContent());
						assertNotNull(signedData);
						final ASN1Set signedDataCRLs = signedData.getCRLs();
						if (signedDataCRLs != null) {
							final Enumeration<ASN1Encodable> crLs = signedDataCRLs.getObjects();
							if (crLs != null) {
								while (crLs.hasMoreElements()) {
									final ASN1Encodable asn1Encodable = crLs.nextElement();
									byte[] digest = DSSUtils.digest(digestAlgorithm, DSSASN1Utils.getDEREncoded(asn1Encodable));
									final DEROctetString derOctetStringDigest = new DEROctetString(digest);
									if (crlHashesList.remove(derOctetStringDigest)) {
										// good
									} else {
										fail("SignedData crl is not present in timestamp!");
									}
								}
							}
						}
						if (!crlHashesList.isEmpty()) {
							fail("Some crls have not been found in SignedData.certificates!");
						}

						ASN1Sequence unsignedAttributesHashIndex = CMSUtils.getUnsignedAttributesHashIndex(atsHashIndexValue);
						List<DEROctetString> unsignedAttrsHashesList = DSSASN1Utils.getDEROctetStrings(unsignedAttributesHashIndex);

						final ASN1EncodableVector asn1EncodableVector = unsignedAttributes.toASN1EncodableVector();
						for (int i = 0; i < asn1EncodableVector.size(); i++) {
							final Attribute unsignedAttribute = (Attribute) asn1EncodableVector.get(i);
							if (attribute == unsignedAttribute) {
								continue; // skip current timestamp
							}
							List<byte[]> octetStringForAtsHashIndex = CMSUtils.getOctetStringForAtsHashIndex(unsignedAttribute, attrType);
							List<DEROctetString> attributeDerOctetStringHashes = octetStringForAtsHashIndex.stream()
									.map(b -> new DEROctetString(DSSUtils.digest(digestAlgorithm, b))).collect(Collectors.toList());
							for (DEROctetString derOctetStringDigest : attributeDerOctetStringHashes) {
								if (unsignedAttrsHashesList.remove(derOctetStringDigest)) {
									// good
								}
								// skip else, as signature may be extended
							}
						}
						if (!unsignedAttrsHashesList.isEmpty()) {
							fail("Some unsigned attrs have not been found in SignedData.certificates!");
						}

						arcTstV3Found = true;
					}

				}
				assertTrue(arcTstV3Found);

			}

		} catch (Exception e) {
			fail(e);
		}
	}
	
	@Override
	protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertNotNull(signatureWrapper.getSignatureValue());
		}
	}
	
	@Override
	protected void checkReportsSignatureIdentifier(Reports reports) {
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		for (SignatureValidationReportType signatureValidationReport : etsiValidationReport.getSignatureValidationReport()) {
			SignatureWrapper signature = diagnosticData.getSignatureById(signatureValidationReport.getSignatureIdentifier().getId());
			
			SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
			assertNotNull(signatureIdentifier);
			
			assertNotNull(signatureIdentifier.getSignatureValue());
			assertArrayEquals(signature.getSignatureValue(), signatureIdentifier.getSignatureValue().getValue());
		}
	}

	@Override
	protected void checkMimeType(DSSDocument signedDocument) {
		super.checkMimeType(signedDocument);
		checkFileExtension(signedDocument);
	}

	protected void checkFileExtension(DSSDocument document) {
		String documentName = document.getName();
		assertNotNull(documentName);

		String extension = Utils.getFileNameExtension(documentName);
		assertNotNull(extension);

		if (SignaturePackaging.DETACHED.equals(getSignatureParameters().getSignaturePackaging())) {
			assertEquals("p7s", extension);
		} else {
			assertEquals("p7m", extension);
		}
	}

	@Override
	protected void checkMimeType(DiagnosticData diagnosticData) {
		super.checkMimeType(diagnosticData);

		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			if (!signatureWrapper.isCounterSignature() && Utils.isStringEmpty(signatureWrapper.getContentHints())) {
				assertNotNull(signatureWrapper.getMimeType());
			} else {
				assertNull(signatureWrapper.getMimeType());
			}
		}
	}

	@Override
	protected MimeType getExpectedMime() {
		return MimeTypeEnum.PKCS7;
	}

	@Override
	protected boolean isBaselineT() {
		SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
		return SignatureLevel.CAdES_BASELINE_LTA.equals(signatureLevel) || SignatureLevel.CAdES_BASELINE_LT.equals(signatureLevel)
				|| SignatureLevel.CAdES_BASELINE_T.equals(signatureLevel);
	}

	@Override
	protected boolean isBaselineLTA() {
		return SignatureLevel.CAdES_BASELINE_LTA.equals(getSignatureParameters().getSignatureLevel());
	}

	@Override
	protected void checkAtsHashTable(List<TimestampWrapper> allTimestamps) {
		super.checkAtsHashTable(allTimestamps);

		for (TimestampWrapper timestampWrapper : allTimestamps) {
			if (TimestampType.ARCHIVE_TIMESTAMP == timestampWrapper.getType() &&
					ArchiveTimestampType.CAdES_V3 == timestampWrapper.getArchiveTimestampType()) {
				assertEquals(ArchiveTimestampHashIndexVersion.ATS_HASH_INDEX_V3, timestampWrapper.getAtsHashIndexVersion());
				assertTrue(timestampWrapper.isAtsHashIndexValid());
				assertTrue(Utils.isCollectionEmpty(timestampWrapper.getAtsHashIndexValidationMessages()));
			}
		}
	}

}
