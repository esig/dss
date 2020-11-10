package eu.europa.esig.dss.pades.validation;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.cades.validation.CAdESDiagnosticDataBuilder;
import eu.europa.esig.dss.diagnostic.jaxb.XmlModification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlModificationDetection;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanTokens;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.pades.validation.timestamp.PdfTimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

/**
 * DiagnosticDataBuilder for a PDF signature
 *
 */
public class PAdESDiagnosticDataBuilder extends CAdESDiagnosticDataBuilder {

	@Override
	public XmlSignature buildDetachedXmlSignature(AdvancedSignature signature) {
		XmlSignature xmlSignature = super.buildDetachedXmlSignature(signature);
		PAdESSignature padesSignature = (PAdESSignature) signature;
		xmlSignature.setPDFRevision(getXmlPDFRevision(padesSignature.getPdfRevision()));
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
			xmlPDFRevision.getSignatureFieldName().addAll(pdfRevision.getFieldNames());
			xmlPDFRevision.setPDFSignatureDictionary(getXmlPDFSignatureDictionary(pdfRevision.getPdfSigDictInfo()));
			xmlPDFRevision
					.setModificationDetection(getXmlModificationDetection(pdfRevision.getModificationDetection()));
			return xmlPDFRevision;
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
			pdfSignatureDictionary.getSignatureByteRange().addAll(pdfSigDict.getByteRange().toBigIntegerList());
			return pdfSignatureDictionary;
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

	@Override
	protected XmlOrphanTokens buildXmlOrphanTokens() {
		buildOrphanRevocationTokensFromCommonSources(); // necessary to collect all data from DSS PDF revisions
		return super.buildXmlOrphanTokens();
	}

	private void buildOrphanRevocationTokensFromCommonSources() {
		for (EncapsulatedRevocationTokenIdentifier<CRL> revocationIdentifier : commonCRLSource
				.getAllRevocationBinaries()) {
			String id = revocationIdentifier.asXmlId();
			if (!xmlRevocationsMap.containsKey(id) && !xmlOrphanRevocationTokensMap.containsKey(id)) {
				createOrphanTokenFromRevocationIdentifier(revocationIdentifier);
			}
		}
		for (EncapsulatedRevocationTokenIdentifier<OCSP> revocationIdentifier : commonOCSPSource
				.getAllRevocationBinaries()) {
			String id = revocationIdentifier.asXmlId();
			if (!xmlRevocationsMap.containsKey(id) && !xmlOrphanRevocationTokensMap.containsKey(id)) {
				createOrphanTokenFromRevocationIdentifier(revocationIdentifier);
			}
		}
	}

}
