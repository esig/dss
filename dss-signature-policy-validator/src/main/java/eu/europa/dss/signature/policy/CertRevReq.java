package eu.europa.dss.signature.policy;

public interface CertRevReq {

	RevReq getEndCertRevReq();

	RevReq getCaCerts();

}