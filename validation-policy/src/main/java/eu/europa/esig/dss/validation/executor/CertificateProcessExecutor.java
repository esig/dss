package eu.europa.esig.dss.validation.executor;

import eu.europa.esig.dss.validation.reports.CertificateReports;

public interface CertificateProcessExecutor extends ProcessExecutor<CertificateReports> {
	
	/**
	 * Allows to specify if of the target certificate present in the Diagnostic Data to be verified
	 * 
	 * @param certificateId {@link String} id of the certificate to be verified
	 */
	void setCertificateId(String certificateId);

}
