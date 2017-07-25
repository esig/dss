package eu.europa.esig.dss.signature.policy;

public interface SigningCertTrustCondition {

	CertificateTrustTrees getSignerTrustTrees();

	CertRevReq getSignerRevReq();

}