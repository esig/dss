package eu.europa.dss.signature.policy;

public interface SigningCertTrustCondition {

	CertificateTrustTrees getSignerTrustTrees();

	CertRevReq getSignerRevReq();

}