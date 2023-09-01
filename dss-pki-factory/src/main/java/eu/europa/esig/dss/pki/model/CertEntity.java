package eu.europa.esig.dss.pki.model;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;

import java.io.Serializable;
import java.security.PrivateKey;
import java.util.List;

public interface CertEntity extends Serializable {


    PrivateKey getPrivateKeyObject();

    List<CertificateToken>  getCertificateChain();

    CertificateToken getCertificateToken();

    EncryptionAlgorithm getEncryptionAlgorithm();




}
