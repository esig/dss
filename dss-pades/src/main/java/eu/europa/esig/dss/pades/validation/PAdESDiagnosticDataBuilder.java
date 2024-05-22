/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.cades.validation.CAdESDiagnosticDataBuilder;
import eu.europa.esig.dss.diagnostic.jaxb.XmlByteRange;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDocMDP;
import eu.europa.esig.dss.diagnostic.jaxb.XmlModification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlModificationDetection;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModifications;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanTokens;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFLockDictionary;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureField;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.pades.validation.timestamp.PdfTimestampToken;
import eu.europa.esig.dss.pdf.SigFieldPermissions;
import eu.europa.esig.dss.pdf.modifications.ObjectModification;
import eu.europa.esig.dss.pdf.modifications.PdfModification;
import eu.europa.esig.dss.pdf.modifications.PdfModificationDetection;
import eu.europa.esig.dss.pdf.modifications.PdfObjectModifications;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * DiagnosticDataBuilder for a PDF signature
 *
 */
public class PAdESDiagnosticDataBuilder extends CAdESDiagnosticDataBuilder {

	/**
	 * Default constructor
	 */
	public PAdESDiagnosticDataBuilder() {
		// empty
	}

	@Override
	public XmlSignature buildDetachedXmlSignature(AdvancedSignature signature) {
		XmlSignature xmlSignature = super.buildDetachedXmlSignature(signature);
		PAdESSignature padesSignature = (PAdESSignature) signature;
		xmlSignature.setPDFRevision(getXmlPDFRevision(padesSignature.getPdfRevision()));
		xmlSignature.setVRIDictionaryCreationTime(padesSignature.getVRICreationTime());
		return xmlSignature;
	}
	
	@Override
	protected XmlTimestamp buildDetachedXmlTimestamp(TimestampToken timestampToken) {
		XmlTimestamp xmlTimestamp = super.buildDetachedXmlTimestamp(timestampToken);
		if (timestampToken instanceof PdfTimestampToken) {
			// for DOCUMENT_TIMESTAMPs
			PdfTimestampToken pdfTimestampToken = (PdfTimestampToken) timestampToken;
			xmlTimestamp.setPDFRevision(getXmlPDFRevision(pdfTimestampToken.getPdfRevision()));
		}
		return xmlTimestamp;
	}

	private XmlPDFRevision getXmlPDFRevision(PdfRevision pdfRevision) {
		if (pdfRevision != null) {
			XmlPDFRevision xmlPDFRevision = new XmlPDFRevision();
			List<PdfSignatureField> fields = pdfRevision.getFields();
			if (Utils.isCollectionNotEmpty(fields)) {
				for (PdfSignatureField field : fields) {
					xmlPDFRevision.getFields().add(getXmlPDFSignatureField(field));
				}
			}
			xmlPDFRevision.setPDFSignatureDictionary(getXmlPDFSignatureDictionary(pdfRevision.getPdfSigDictInfo()));
			xmlPDFRevision.setModificationDetection(getXmlModificationDetection(pdfRevision.getModificationDetection()));
			return xmlPDFRevision;
		}
		return null;
	}

	private XmlPDFSignatureField getXmlPDFSignatureField(PdfSignatureField pdfSignatureField) {
		XmlPDFSignatureField xmlPdfSignatureField = new XmlPDFSignatureField();
		xmlPdfSignatureField.setName(pdfSignatureField.getFieldName());
		xmlPdfSignatureField.setSigFieldLock(getXmlPDFLockDictionary(pdfSignatureField.getLockDictionary()));
		return xmlPdfSignatureField;
	}

	private XmlPDFLockDictionary getXmlPDFLockDictionary(SigFieldPermissions lockDictionary) {
		if (lockDictionary != null) {
			XmlPDFLockDictionary xmlPDFLockDictionary = new XmlPDFLockDictionary();
			xmlPDFLockDictionary.setAction(lockDictionary.getAction());
			if (Utils.isCollectionNotEmpty(lockDictionary.getFields())) {
				xmlPDFLockDictionary.getFields().addAll(lockDictionary.getFields());
			}
			if (lockDictionary.getCertificationPermission() != null) {
				xmlPDFLockDictionary.setPermissions(lockDictionary.getCertificationPermission());
			}
			return xmlPDFLockDictionary;
		}
		return null;
	}

	private XmlPDFSignatureDictionary getXmlPDFSignatureDictionary(PdfSignatureDictionary pdfSigDict) {
		if (pdfSigDict != null) {
			XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
			pdfSignatureDictionary.setSignerName(emptyToNull(pdfSigDict.getSignerName()));
			pdfSignatureDictionary.setType(emptyToNull(pdfSigDict.getType()));
			pdfSignatureDictionary.setFilter(emptyToNull(pdfSigDict.getFilter()));
			pdfSignatureDictionary.setSubFilter(emptyToNull(pdfSigDict.getSubFilter()));
			pdfSignatureDictionary.setContactInfo(emptyToNull(pdfSigDict.getContactInfo()));
			pdfSignatureDictionary.setLocation(emptyToNull(pdfSigDict.getLocation()));
			pdfSignatureDictionary.setReason(emptyToNull(pdfSigDict.getReason()));
			pdfSignatureDictionary.setSignatureByteRange(getXmlByteRange(pdfSigDict.getByteRange()));
			pdfSignatureDictionary.setDocMDP(getXmlDocMDP(pdfSigDict.getDocMDP()));
			pdfSignatureDictionary.setFieldMDP(getXmlPDFLockDictionary(pdfSigDict.getFieldMDP()));
			pdfSignatureDictionary.setConsistent(pdfSigDict.isConsistent());
			return pdfSignatureDictionary;
		}
		return null;
	}

	private XmlByteRange getXmlByteRange(ByteRange byteRange) {
		XmlByteRange xmlByteRange = new XmlByteRange();
		xmlByteRange.getValue().addAll(byteRange.toBigIntegerList());
		xmlByteRange.setValid(byteRange.isValid());
		return xmlByteRange;
	}

	private XmlDocMDP getXmlDocMDP(CertificationPermission certificationPermission) {
		if (certificationPermission != null) {
			XmlDocMDP xmlDocMDP = new XmlDocMDP();
			xmlDocMDP.setPermissions(certificationPermission);
			return xmlDocMDP;
		}
		return null;
	}

	private XmlModificationDetection getXmlModificationDetection(PdfModificationDetection modificationDetection) {
		if (modificationDetection != null && modificationDetection.areModificationsDetected()) {
			XmlModificationDetection xmlModificationDetection = new XmlModificationDetection();

			List<PdfModification> annotationOverlaps = modificationDetection.getAnnotationOverlaps();
			if (Utils.isCollectionNotEmpty(annotationOverlaps)) {
				xmlModificationDetection.getAnnotationOverlap().addAll(getXmlModifications(annotationOverlaps));
			}

			List<PdfModification> visualDifferences = modificationDetection.getVisualDifferences();
			if (Utils.isCollectionNotEmpty(visualDifferences)) {
				xmlModificationDetection.getVisualDifference().addAll(getXmlModifications(visualDifferences));
			}

			List<PdfModification> pageDifferences = modificationDetection.getPageDifferences();
			if (Utils.isCollectionNotEmpty(pageDifferences)) {
				xmlModificationDetection.getPageDifference().addAll(getXmlModifications(pageDifferences));
			}

			PdfObjectModifications objectModifications = modificationDetection.getObjectModifications();
			if (!objectModifications.isEmpty()) {
				xmlModificationDetection.setObjectModifications(getXmlObjectModifications(objectModifications));
			}

			return xmlModificationDetection;
		}
		return null;
	}

	private List<XmlModification> getXmlModifications(List<PdfModification> modifications) {
		List<XmlModification> xmlModifications = new ArrayList<>();
		if (Utils.isCollectionNotEmpty(modifications)) {
			for (PdfModification pdfModification : modifications) {
				xmlModifications.add(getXmlModification(pdfModification));
			}
		}
		return xmlModifications;
	}

	private XmlModification getXmlModification(PdfModification pdfModification) {
		XmlModification xmlModification = new XmlModification();
		xmlModification.setPage(BigInteger.valueOf(pdfModification.getPage()));
		return xmlModification;
	}

	private XmlObjectModifications getXmlObjectModifications(PdfObjectModifications objectModifications) {
		XmlObjectModifications xmlObjectModifications = new XmlObjectModifications();
		for (ObjectModification modification : objectModifications.getSecureChanges()) {
			xmlObjectModifications.getExtensionChanges().add(getXmlObjectModification(modification));
		}
		for (ObjectModification modification : objectModifications.getFormFillInAndSignatureCreationChanges()) {
			xmlObjectModifications.getSignatureOrFormFill().add(getXmlObjectModification(modification));
		}
		for (ObjectModification modification : objectModifications.getAnnotCreationChanges()) {
			xmlObjectModifications.getAnnotationChanges().add(getXmlObjectModification(modification));
		}
		for (ObjectModification modification : objectModifications.getUndefinedChanges()) {
			xmlObjectModifications.getUndefined().add(getXmlObjectModification(modification));
		}
		return xmlObjectModifications;
	}

	private XmlObjectModification getXmlObjectModification(ObjectModification objectModification) {
		XmlObjectModification xmlObjectModification = new XmlObjectModification();
		xmlObjectModification.setValue(objectModification.getObjectTree().toString());
		xmlObjectModification.setAction(objectModification.getActionType());
		xmlObjectModification.setFieldName(objectModification.getFieldName());
		xmlObjectModification.setType(objectModification.getType());
		return xmlObjectModification;
	}

	@Override
	protected XmlOrphanTokens buildXmlOrphanTokens() {
		buildOrphanTokensFromDocumentSources(); // necessary to collect all data from DSS PDF revisions
		return super.buildXmlOrphanTokens();
	}

	private void buildOrphanTokensFromDocumentSources() {
		for (CertificateToken certificateToken : documentCertificateSource.getCertificates()) {
			String id = certificateToken.getDSSIdAsString();
			if (!xmlCertsMap.containsKey(id) && !xmlOrphanCertificateTokensMap.containsKey(id)) {
				buildXmlOrphanCertificateToken(certificateToken);
			}
		}
		for (EncapsulatedRevocationTokenIdentifier<CRL> revocationIdentifier : documentCRLSource.getAllRevocationBinaries()) {
			String id = revocationIdentifier.asXmlId();
			if (!xmlRevocationsMap.containsKey(id) && !xmlOrphanRevocationTokensMap.containsKey(id)) {
				createOrphanTokenFromRevocationIdentifier(revocationIdentifier);
			}
		}
		for (EncapsulatedRevocationTokenIdentifier<OCSP> revocationIdentifier : documentOCSPSource.getAllRevocationBinaries()) {
			String id = revocationIdentifier.asXmlId();
			if (!xmlRevocationsMap.containsKey(id) && !xmlOrphanRevocationTokensMap.containsKey(id)) {
				createOrphanTokenFromRevocationIdentifier(revocationIdentifier);
			}
		}
	}

}
