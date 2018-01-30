package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import java.util.List;

import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public interface TrustedServiceFilter {

	List<TrustedServiceWrapper> filter(List<TrustedServiceWrapper> trustedServices);

}
