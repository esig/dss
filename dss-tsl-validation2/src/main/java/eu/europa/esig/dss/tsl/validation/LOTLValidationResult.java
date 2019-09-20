package eu.europa.esig.dss.tsl.validation;

import java.util.Date;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;

public class LOTLValidationResult extends AbstractValidationResult {

	public LOTLValidationResult(Indication indication, SubIndication subIndication, Date signingTime, CertificateToken signingCertificate) {
		super(indication, subIndication, signingTime, signingCertificate);
	}
	
	public LOTLValidationResult(String errorMessage) {
		super(errorMessage);
	}

}
