package eu.europa.esig.dss.signature.policy;

public interface CertRevReq {

	RevReq getEndCertRevReq();

	RevReq getCaCerts();

}