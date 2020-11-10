package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentDiagnosticDataBuilder;

/**
 * DiagnosticDataBuilder for a CMS signature
 *
 */
public class CAdESDiagnosticDataBuilder extends SignedDocumentDiagnosticDataBuilder {

	@Override
	public XmlSignature buildDetachedXmlSignature(AdvancedSignature signature) {
		XmlSignature xmlSignature = super.buildDetachedXmlSignature(signature);
		CAdESSignature cadesSignature = (CAdESSignature) signature;
		xmlSignature.setContentIdentifier(cadesSignature.getContentIdentifier());
		xmlSignature.setContentHints(cadesSignature.getContentHints());
		xmlSignature.setSignerInformationStore(
				getXmlSignerInformationStore(cadesSignature.getSignerInformationStoreInfos()));
		return xmlSignature;
	}

}
