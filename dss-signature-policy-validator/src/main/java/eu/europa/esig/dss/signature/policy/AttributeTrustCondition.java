package eu.europa.esig.dss.signature.policy;

public interface AttributeTrustCondition {

	boolean isAttributeMandated();

	HowCertAttribute getHowCertAttribute();

	CertificateTrustTrees getAttrCertificateTrustTrees();

	CertRevReq getAttrRevReq();

	AttributeConstraints getAttributeConstraints();

}