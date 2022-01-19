package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.CertificateList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a source of CRL tokens extracted from a PDF's CMS
 *
 */
public class PdfCmsCRLSource extends OfflineCRLSource {

    private static final Logger LOG = LoggerFactory.getLogger(PdfCmsCRLSource.class);

    /**
     * The default constructor
     *
     * @param signedAttributes {@link AttributeTable}
     */
    public PdfCmsCRLSource(AttributeTable signedAttributes) {
        extractCRLArchivalValues(signedAttributes);
    }

    /**
     * Extract the CRL Archival values
     *
     * @param signedAttributes {@link AttributeTable}
     */
    private void extractCRLArchivalValues(AttributeTable signedAttributes) {
        if (signedAttributes != null) {
            final ASN1Encodable attValue = DSSASN1Utils.getAsn1Encodable(signedAttributes, OID.adbe_revocationInfoArchival);
            RevocationInfoArchival revValues = PAdESUtils.getRevocationInfoArchival(attValue);
            if (revValues != null) {
                for (final CertificateList revValue : revValues.getCrlVals()) {
                    try {
                        addBinary(CRLUtils.buildCRLBinary(revValue.getEncoded()),
                                RevocationOrigin.ADBE_REVOCATION_INFO_ARCHIVAL);
                    } catch (Exception e) {
                        LOG.warn("Could not convert CertificateList to CRLBinary : {}", e.getMessage());
                    }
                }
            }
        }
    }

}
