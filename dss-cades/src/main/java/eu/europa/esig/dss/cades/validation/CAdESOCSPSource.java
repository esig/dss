package eu.europa.esig.dss.cades.validation;

import java.util.Collection;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.validation.CMSOCSPSource;
import eu.europa.esig.dss.x509.RevocationOrigin;

@SuppressWarnings("serial")
public class CAdESOCSPSource extends CMSOCSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESOCSPSource.class);

	CAdESOCSPSource(CMSSignedData cms, AttributeTable unsignedAttributes) {
		super(cms, unsignedAttributes);
	}

	@Override
	protected void collectFromSignedData() {
		addBasicOcspRespFrom_id_ri_ocsp_response();
		addBasicOcspRespFrom_id_pkix_ocsp_basic();
	}

	private void addBasicOcspRespFrom_id_ri_ocsp_response() {
		final Store otherRevocationInfo = cmsSignedData.getOtherRevocationInfo(CMSObjectIdentifiers.id_ri_ocsp_response);
		final Collection otherRevocationInfoMatches = otherRevocationInfo.getMatches(null);
		for (final Object object : otherRevocationInfoMatches) {
			if (object instanceof DERSequence) {
				final DERSequence otherRevocationInfoMatch = (DERSequence) object;
				final BasicOCSPResp basicOCSPResp;
				if (otherRevocationInfoMatch.size() == 4) {
					basicOCSPResp = CMSUtils.getBasicOcspResp(otherRevocationInfoMatch);
				} else {
					final OCSPResp ocspResp = CMSUtils.getOcspResp(otherRevocationInfoMatch);
					basicOCSPResp = CMSUtils.getBasicOcspResp(ocspResp);
				}
				addBasicOcspResp(basicOCSPResp, RevocationOrigin.INTERNAL_REVOCATION_VALUES);
			} else {
				LOG.warn("Unsupported object type for id_ri_ocsp_response (SHALL be DER encoding) : {}",
						object.getClass().getSimpleName());
			}
		}
	}

	private void addBasicOcspRespFrom_id_pkix_ocsp_basic() {
		final Store otherRevocationInfo = cmsSignedData.getOtherRevocationInfo(OCSPObjectIdentifiers.id_pkix_ocsp_basic);
		final Collection otherRevocationInfoMatches = otherRevocationInfo.getMatches(null);
		for (final Object object : otherRevocationInfoMatches) {
			if (object instanceof DERSequence) {
				final DERSequence otherRevocationInfoMatch = (DERSequence) object;
				final BasicOCSPResp basicOCSPResp = CMSUtils.getBasicOcspResp(otherRevocationInfoMatch);
				addBasicOcspResp(basicOCSPResp, RevocationOrigin.INTERNAL_REVOCATION_VALUES);
			} else {
				LOG.warn("Unsupported object type for id_pkix_ocsp_basic (SHALL be DER encoding) : {}",
						object.getClass().getSimpleName());
			}
		}
	}

}
