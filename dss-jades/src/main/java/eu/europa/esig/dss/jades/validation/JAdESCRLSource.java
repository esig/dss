package eu.europa.esig.dss.jades.validation;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.enumerations.PKIEncoding;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.utils.Utils;

public class JAdESCRLSource extends OfflineCRLSource {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESCRLSource.class);

	private static final long serialVersionUID = -8088419662779006608L;

	private transient final JAdESEtsiUHeader etsiUHeader;

	public JAdESCRLSource(JAdESEtsiUHeader etsiUHeader) {
		Objects.requireNonNull(etsiUHeader, "etsiUComponents cannot be null");
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
			extractCRLValues((Map<?, ?>) attribute.getValue(), RevocationOrigin.REVOCATION_VALUES);
		}
	}
	
	private void extractAttributeRevocationValues(JAdESAttribute attribute) {
		if (JAdESHeaderParameterNames.AR_VALS.equals(attribute.getHeaderName())) {
			extractCRLValues((Map<?, ?>) attribute.getValue(), RevocationOrigin.ATTRIBUTE_REVOCATION_VALUES);
		}
	}
	
	private void extractTimestampValidationData(JAdESAttribute attribute) {
		if (JAdESHeaderParameterNames.TST_VD.equals(attribute.getHeaderName())) {
			Map<?, ?> tstVd = (Map<?, ?>) attribute.getValue();
			Map<?, ?> revVals = (Map<?, ?>) tstVd.get(JAdESHeaderParameterNames.R_VALS);
			if (Utils.isMapNotEmpty(revVals)) {
				extractCRLValues(revVals, RevocationOrigin.TIMESTAMP_VALIDATION_DATA);
			}
		}
	}
	
	private void extractCompleteRevocationRefs(JAdESAttribute attribute) {
		if (JAdESHeaderParameterNames.R_REFS.equals(attribute.getHeaderName())) {
			extractCRLReferences((Map<?, ?>) attribute.getValue(), RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
		}
	}
	
	private void extractAttributeRevocationRefs(JAdESAttribute attribute) {
		if (JAdESHeaderParameterNames.AR_REFS.equals(attribute.getHeaderName())) {
			extractCRLReferences((Map<?, ?>) attribute.getValue(), RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS);
		}
	}

	private void extractCRLValues(Map<?, ?> rVals, RevocationOrigin origin) {
		List<?> crlValues = (List<?>) rVals.get(JAdESHeaderParameterNames.CRL_VALS);
		if (Utils.isCollectionNotEmpty(crlValues)) {
			for (Object item : crlValues) {
				if (item instanceof Map) {
					Map<?, ?> pkiOb = (Map<?, ?>) item;
					String encoding = (String) pkiOb.get(JAdESHeaderParameterNames.ENCODING);
					if (Utils.isStringEmpty(encoding) || Utils.areStringsEqual(PKIEncoding.DER.getUri(), encoding)) {
						String crlValueDerB64 = (String) pkiOb.get(JAdESHeaderParameterNames.VAL);
						add(crlValueDerB64, origin);
					} else {
						LOG.warn("Unsupported encoding '{}'", encoding);
					}
				} else {
					LOG.warn("Unsupported type for {} : {}", JAdESHeaderParameterNames.CRL_VALS, item.getClass());
				}
			}
		}
	}

	private void add(String crlValueDerB64, RevocationOrigin origin) {
		try {
			addBinary(CRLUtils.buildCRLBinary(Utils.fromBase64(crlValueDerB64)), origin);
		} catch (Exception e) {
			LOG.error("Unable to extract CRL from '{}'", crlValueDerB64, e);
		}
	}

	private void extractCRLReferences(Map<?, ?> rRefs, RevocationRefOrigin origin) {
		List<?> crlRefs = (List<?>) rRefs.get(JAdESHeaderParameterNames.CRL_REFS);
		if (Utils.isCollectionNotEmpty(crlRefs)) {
			for (Object item : crlRefs) {
				if (item instanceof Map) {
					CRLRef crlRef = JAdESRevocationRefExtractionUtils.createCRLRef((Map<?, ?>) item);
					if (crlRef != null) {
						addRevocationReference(crlRef, origin);
					}
				}
			}
		}
	}

}
