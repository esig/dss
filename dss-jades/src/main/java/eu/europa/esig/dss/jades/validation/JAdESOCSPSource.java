package eu.europa.esig.dss.jades.validation;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.PKIEncoding;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.utils.Utils;

public class JAdESOCSPSource extends OfflineOCSPSource {

	private static final long serialVersionUID = -6522217477882736259L;

	private static final Logger LOG = LoggerFactory.getLogger(JAdESOCSPSource.class);

	private final JWS jws;

	public JAdESOCSPSource(JWS jws) {
		Objects.requireNonNull(jws, "JWS cannot be null");
		this.jws = jws;

		extractEtsiU();
	}

	private void extractEtsiU() {
		List<?> etsiU = JAdESUtils.getEtsiU(jws);
		if (Utils.isCollectionEmpty(etsiU)) {
			return;
		}

		for (Object item : etsiU) {
			if (item instanceof Map) {
				Map<?, ?> jsonObject = (Map<?, ?>) item;

				Map<?, ?> rVals = (Map<?, ?>) jsonObject.get(JAdESHeaderParameterNames.R_VALS);
				if (rVals != null) {
					extractOCSPValues(rVals, RevocationOrigin.REVOCATION_VALUES);
				}

				Map<?, ?> arVals = (Map<?, ?>) jsonObject.get(JAdESHeaderParameterNames.AR_VALS);
				if (arVals != null) {
					extractOCSPValues(arVals, RevocationOrigin.ATTRIBUTE_REVOCATION_VALUES);
				}

				Map<?, ?> rRefs = (Map<?, ?>) jsonObject.get(JAdESHeaderParameterNames.R_REFS);
				if (rRefs != null) {
					extractOCSPReferences(rRefs, RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
				}

				Map<?, ?> arRefs = (Map<?, ?>) jsonObject.get(JAdESHeaderParameterNames.AR_REFS);
				if (arRefs != null) {
					extractOCSPReferences(arRefs, RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS);
				}
			}
		}
	}

	private void extractOCSPValues(Map<?, ?> rVals, RevocationOrigin origin) {
		List<?> ocspValues = (List<?>) rVals.get(JAdESHeaderParameterNames.OCSP_VALS);
		if (Utils.isCollectionNotEmpty(ocspValues)) {
			for (Object item : ocspValues) {
				if (item instanceof Map) {
					Map<?, ?> pkiOb = (Map<?, ?>) item;
					String encoding = (String) pkiOb.get(JAdESHeaderParameterNames.ENCODING);
					if (Utils.isStringEmpty(encoding) || Utils.areStringsEqual(PKIEncoding.DER.getUri(), encoding)) {
						String ocspValueDerB64 = (String) pkiOb.get(JAdESHeaderParameterNames.VAL);
						add(ocspValueDerB64, origin);
					} else {
						LOG.warn("Unsupported encoding '{}'", encoding);
					}
				} else {
					LOG.warn("Unsupported type for {} : {}", JAdESHeaderParameterNames.OCSP_VALS, item.getClass());
				}
			}
		}
	}

	private void add(String ocspValueDerB64, RevocationOrigin origin) {
		try {
			addBinary(OCSPResponseBinary.build(DSSRevocationUtils.loadOCSPBase64Encoded(ocspValueDerB64)), origin);
		} catch (Exception e) {
			LOG.error("Unable to extract OCSP from '{}'", ocspValueDerB64, e);
		}
	}

	private void extractOCSPReferences(Map<?, ?> rRefs, RevocationRefOrigin origin) {
		List<?> ocspRefs = (List<?>) rRefs.get(JAdESHeaderParameterNames.OCSP_REFS);
		if (Utils.isCollectionNotEmpty(ocspRefs)) {
			for (Object item : ocspRefs) {
				if (item instanceof Map) {
					OCSPRef ocspRef = JAdESRevocationRefExtractionUtils.createOCSPRef((Map<?, ?>) item);
					if (ocspRef != null) {
						addRevocationReference(ocspRef, origin);
					}
				}
			}
		}
	}

}
