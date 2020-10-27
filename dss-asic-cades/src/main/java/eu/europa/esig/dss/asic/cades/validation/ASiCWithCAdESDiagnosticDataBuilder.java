package eu.europa.esig.dss.asic.cades.validation;

import eu.europa.esig.dss.asic.common.validation.ASiCContainerDiagnosticDataBuilder;
import eu.europa.esig.dss.cades.validation.CAdESDiagnosticDataBuilder;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.validation.AdvancedSignature;

public class ASiCWithCAdESDiagnosticDataBuilder extends ASiCContainerDiagnosticDataBuilder {

	@Override
	public XmlSignature buildDetachedXmlSignature(AdvancedSignature signature) {
		return new CAdESDiagnosticDataBuilder().buildDetachedXmlSignature(signature);
	}

}
