package eu.europa.esig.dss.validation.process.art32.qualification.checks.filter;

import java.util.List;

import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProvider;

public interface TrustedServiceFilter {

	List<XmlTrustedServiceProvider> filter(List<XmlTrustedServiceProvider> tsps);

}
