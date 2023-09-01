package eu.europa.esig.dss.pki.jaxb.dto;

public enum CertificatePolicyOids {

    QCP_N("0.4.0.94112.1.0"), QCP_L("0.4.0.94112.1.1"), QCP_N_QSCD("0.4.0.94112.1.2"), QCP_L_QSCD(
            "0.4.0.94112.1.3"), QCP_W("0.4.0.94112.1.4"), QCP_SSCD("0.4.0.1456.1.1"), QCP("0.4.0.1456.1.2");

    private final String oid;

    CertificatePolicyOids(String oid) {
        this.oid = oid;
    }

    public String getOid() {
        return oid;
    }

}
