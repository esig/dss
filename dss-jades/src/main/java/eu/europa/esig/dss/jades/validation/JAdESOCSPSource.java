package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.enumerations.PKIEncoding;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Extracts and stores OCSPs from a JAdES signature
 */
public class JAdESOCSPSource extends OfflineOCSPSource {

	private static final long serialVersionUID = -6522217477882736259L;

	private static final Logger LOG = LoggerFactory.getLogger(JAdESOCSPSource.class);

	/** Represents the unsigned 'etsiU' header */
	private transient final JAdESEtsiUHeader etsiUHeader;

	/**
	 * Default constructor
	 *
	 * @param etsiUHeader {@link JAdESEtsiUHeader} unsigned component
	 */
	public JAdESOCSPSource(JAdESEtsiUHeader etsiUHeader) {
		Objects.requireNonNull(etsiUHeader, "etsiUHeader cannot be null");
		this.etsiUHeader = etsiUHeader;

		extractEtsiU();
	}

	private void extractEtsiU() {
		if (!etsiUHeader.isExist()) {
			return;
		}

		for (JAdESAttribute attribute : etsiUHeader.getAttributes()) {
			extractRevocationValues(attribute);
			extractAttributeRevocationValues(attribute);
			extractTimestampValidationData(attribute);

			extractCompleteRevocationRefs(attribute);
			extractAttributeRevocationRefs(attribute);
		}
	}
	
	private void extractRevocationValues(JAdESAttribute attribute) {
		if (JAdESHeaderParameterNames.R_VALS.equals(attribute.getHeaderName())) {
			extractOCSPValues((Map<?, ?>) attribute.getValue(), RevocationOrigin.REVOCATION_VALUES);
		}
	}
	
	private void extractAttributeRevocationValues(JAdESAttribute attribute) {
		if (JAdESHeaderParameterNames.AR_VALS.equals(attribute.getHeaderName())) {
			extractOCSPValues((Map<?, ?>) attribute.getValue(), RevocationOrigin.ATTRIBUTE_REVOCATION_VALUES);
		}
	}
	
	private void extractTimestampValidationData(JAdESAttribute attribute) {
		if (JAdESHeaderParameterNames.TST_VD.equals(attribute.getHeaderName())) {
			Map<?, ?> tstVd = (Map<?, ?>) attribute.getValue();
			Map<?, ?> revVals = (Map<?, ?>) tstVd.get(JAdESHeaderParameterNames.R_VALS);
			if (Utils.isMapNotEmpty(revVals)) {
				extractOCSPValues(revVals, RevocationOrigin.TIMESTAMP_VALIDATION_DATA);
			}
		}
	}
	
	private void extractCompleteRevocationRefs(JAdESAttribute attribute) {
		if (JAdESHeaderParameterNames.R_REFS.equals(attribute.getHeaderName())) {
			extractOCSPReferences((Map<?, ?>) attribute.getValue(), RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
		}
	}
	
	private void extractAttributeRevocationRefs(JAdESAttribute attribute) {
		if (JAdESHeaderParameterNames.AR_REFS.equals(attribute.getHeaderName())) {
			extractOCSPReferences((Map<?, ?>) attribute.getValue(), RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS);
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
