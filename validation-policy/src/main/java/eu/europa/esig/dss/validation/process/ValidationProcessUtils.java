package eu.europa.esig.dss.validation.process;

import java.util.Date;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;

public class ValidationProcessUtils {
	
	/*
	 * RFC 2560 : 4.2.2.2.1  Revocation Checking of an Authorized Responder
	 * 
	 * A CA may specify that an OCSP client can trust a responder for the
	 * lifetime of the responder's certificate. The CA does so by including
	 * the extension id-pkix-ocsp-nocheck.
	 */
	public static boolean isRevocationNoNeedCheck(CertificateWrapper certificate, Date controlTime) {
		if (certificate.isIdPkixOcspNoCheck()) {
			return controlTime.compareTo(certificate.getNotBefore()) >= 0 && controlTime.compareTo(certificate.getNotAfter()) <= 0;
		}
		return false;
	}
	
	/**
	 * Checks if the given conclusion is allowed as a basic signature validation in order to continue
	 * the validation process with Long-Term Validation Data
	 * 
	 * @param conclusion {@link XmlConclusion} to validate
	 * @return TRUE if the result is allowed to continue the validation process, FALSE otherwise
	 */
	public static boolean isAllowedBasicSignatureValidation(XmlConclusion conclusion) {
		return Indication.PASSED.equals(conclusion.getIndication()) || (Indication.INDETERMINATE.equals(conclusion.getIndication())
				&& (SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(conclusion.getSubIndication())
						|| SubIndication.REVOKED_NO_POE.equals(conclusion.getSubIndication()) 
						|| SubIndication.REVOKED_CA_NO_POE.equals(conclusion.getSubIndication())
						|| SubIndication.TRY_LATER.equals(conclusion.getSubIndication())
						|| SubIndication.OUT_OF_BOUNDS_NO_POE.equals(conclusion.getSubIndication()) ));
	}
	
	/**
	 * Returns a revocation data used for basic signature validation
	 * 
	 * @param certificate {@link CertificateWrapper} to get a latest applicable revocation data for
	 * @param bbb {@link XmlBasicBuildingBlocks} validation of a token
	 * @return {@link CertificateRevocationWrapper}
	 */
	public static CertificateRevocationWrapper getLatestAcceptableRevocationData(CertificateWrapper certificate, XmlBasicBuildingBlocks bbb) {
		if (bbb != null && bbb.getXCV() != null) {
			for (XmlSubXCV subXCV : bbb.getXCV().getSubXCV()) {
				if (certificate.getId().equals(subXCV.getId()) && subXCV.getRFC() != null) {
					return certificate.getRevocationDataById(subXCV.getRFC().getId());
				}
			}
		}
		return null;
	}

}
