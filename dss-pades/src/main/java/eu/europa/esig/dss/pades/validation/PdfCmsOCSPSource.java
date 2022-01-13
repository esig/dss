package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a source of OCSP tokens extracted from a PDF's CMS
 *
 */
public class PdfCmsOCSPSource extends OfflineOCSPSource {

    private static final Logger LOG = LoggerFactory.getLogger(PdfCmsOCSPSource.class);

    /**
     * The default constructor
     *
     * @param signedAttributes {@link AttributeTable}
     */
    public PdfCmsOCSPSource(AttributeTable signedAttributes) {
        extractOCSPArchivalValues(signedAttributes);
    }

    private void extractOCSPArchivalValues(AttributeTable signedAttributes) {
        if (signedAttributes != null) {
            final ASN1Encodable attValue = DSSASN1Utils.getAsn1Encodable(signedAttributes, OID.adbe_revocationInfoArchival);
            if (attValue != null) {
                RevocationInfoArchival revocationArchival = PAdESUtils.getRevocationInfoArchival(attValue);
                if (revocationArchival != null) {
                    for (final OCSPResponse ocspResponse : revocationArchival.getOcspVals()) {
                        try {
                            BasicOCSPResp basicOCSPResponse = DSSASN1Utils.toBasicOCSPResp(ocspResponse);
                            addBinary(OCSPResponseBinary.build(basicOCSPResponse),
                                    RevocationOrigin.ADBE_REVOCATION_INFO_ARCHIVAL);
                        } catch (OCSPException e) {
                            LOG.warn("Error while extracting OCSPResponse from Revocation Info Archivals (ADBE) : {}",
                                    e.getMessage());
                        }
                    }
                }
            }
        }
    }

}
