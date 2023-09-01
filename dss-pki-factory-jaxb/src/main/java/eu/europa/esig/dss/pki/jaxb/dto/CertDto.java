package eu.europa.esig.dss.pki.jaxb.dto;

import java.util.List;

public class CertDto {

    private String key;
    private String name;
    private String issuerKey;
    private String issuerName;
    private List<String> crossCertKeys;
    private boolean expired;
    private boolean revoked;
    private boolean tsa;
    private boolean ocsp;
    private boolean trustAnchor;
    private boolean toBeIgnored;

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getIssuerKey() {
        return issuerKey;
    }

    public void setIssuerKey(String issuerKey) {
        this.issuerKey = issuerKey;
    }

    public String getIssuerName() {
        return issuerName;
    }

    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    public List<String> getCrossCertKeys() {
        return crossCertKeys;
    }

    public void setCrossCertKeys(List<String> crossCertKeys) {
        this.crossCertKeys = crossCertKeys;
    }

    public boolean isExpired() {
        return expired;
    }

    public void setExpired(boolean expired) {
        this.expired = expired;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
    }

    public boolean isTsa() {
        return tsa;
    }

    public void setTsa(boolean tsa) {
        this.tsa = tsa;
    }

    public boolean isOcsp() {
        return ocsp;
    }

    public void setOcsp(boolean ocsp) {
        this.ocsp = ocsp;
    }

    public boolean isTrustAnchor() {
        return trustAnchor;
    }

    public void setTrustAnchor(boolean trustAnchor) {
        this.trustAnchor = trustAnchor;
    }

    public boolean isToBeIgnored() {
        return toBeIgnored;
    }

    public void setToBeIgnored(boolean toBeIgnored) {
        this.toBeIgnored = toBeIgnored;
    }

}
