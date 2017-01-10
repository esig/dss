package eu.europa.esig.dss.validation.process.art32.qualification.checks;

import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedService;

public interface TrustedServiceCondition {

	boolean isConsistent(XmlTrustedService trustedService);

}
