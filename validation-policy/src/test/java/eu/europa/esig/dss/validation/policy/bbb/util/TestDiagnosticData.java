package eu.europa.esig.dss.validation.policy.bbb.util;

import java.util.ArrayList;

import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;

public class TestDiagnosticData extends DiagnosticData {
	
	public void addXmlSignature(XmlSignature xmlSig) {
		if(signature == null) {
			signature = new ArrayList<XmlSignature>();
		}
		signature.add(xmlSig);
	}
}
