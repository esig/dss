package eu.europa.esig.dss.signature.policy;

import java.util.List;

public interface SignerRules {

	Boolean getExternalSignedData();

	List<String> getMandatedSignedAttr();

	List<String> getMandatedUnsignedAttr();

	CertRefReq getMandatedCertificateRef();

	CertInfoReq getMandatedCertificateInfo();

	List<SignPolExtn> getSignPolExtensions();

}