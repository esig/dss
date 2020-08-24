package eu.europa.esig.dss.xades.validation;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.validation.AbstractSignatureIdentifierBuilder;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Paths;

public class XAdESSignatureIdentiferBuilder extends AbstractSignatureIdentifierBuilder {

	public XAdESSignatureIdentiferBuilder(XAdESSignature signature) {
		super(signature);
	}

	@Override
	protected Integer getCounterSignaturePosition(AdvancedSignature masterSignature) {
		XAdESSignature xadesMasterSignature = (XAdESSignature) masterSignature;
		XAdESSignature xadesSignature = (XAdESSignature) signature;
		
		int counter = 0;
		for (AdvancedSignature counterSignature : xadesMasterSignature.getCounterSignatures()) {
			XAdESSignature xadesCounterSignature = (XAdESSignature) counterSignature;
			if (xadesSignature.getSignatureElement() == xadesCounterSignature.getSignatureElement()) {
				break;
			}
			++counter;
		}
		
		return counter;
	}

	@Override
	protected Integer getSignatureFilePosition() {
		XAdESSignature xadesSignature = (XAdESSignature) signature;
		Element signatureElement = xadesSignature.getSignatureElement();
		Document document = signatureElement.getOwnerDocument();
		final NodeList signatureNodeList = DomUtils.getNodeList(document, XAdES132Paths.ALL_SIGNATURE_WITH_NO_COUNTERSIGNATURE_AS_PARENT_PATH);
		
		int counter = 0;
		while (counter < signatureNodeList.getLength()) {
			if (signatureElement == (Element) signatureNodeList.item(counter)) {
				break;
			}
			++counter;
		}
		
		return counter;
	}

}
