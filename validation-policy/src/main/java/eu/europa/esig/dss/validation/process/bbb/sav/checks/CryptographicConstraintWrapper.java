package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.jaxb.policy.Algo;
import eu.europa.esig.jaxb.policy.AlgoExpirationDate;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;
import eu.europa.esig.jaxb.policy.ListAlgo;

public class CryptographicConstraintWrapper {

	private static final Logger LOG = LoggerFactory.getLogger(CryptographicConstraintWrapper.class);

	private static final String DEFAULT_DATE_FORMAT = "yyyy-MM-dd";

	private final CryptographicConstraint constraint;

	public CryptographicConstraintWrapper(CryptographicConstraint constraint) {
		this.constraint = constraint;
	}

	public List<String> getSupportedEncryptionAlgorithms() {
		return extract(constraint.getAcceptableEncryptionAlgo());
	}

	public List<String> getSupportedDigestAlgorithms() {
		return extract(constraint.getAcceptableDigestAlgo());
	}

	public Map<String, Integer> getMinimumKeySizes() {
		Map<String, Integer> result = new HashMap<String, Integer>();
		ListAlgo miniPublicKeySize = constraint.getMiniPublicKeySize();
		if (miniPublicKeySize != null && Utils.isCollectionNotEmpty(miniPublicKeySize.getAlgo())) {
			for (Algo algo : miniPublicKeySize.getAlgo()) {
				String encryptionAlgo = algo.getValue();
				String miniKeySize = algo.getSize();
				if (Utils.isStringDigits(miniKeySize)) {
					result.put(encryptionAlgo, Integer.valueOf(miniKeySize));
				} else {
					result.put(encryptionAlgo, 0);
				}
			}
		}
		return result;
	}

	public Map<String, Date> getExpirationTimes() {
		Map<String, Date> result = new HashMap<String, Date>();
		AlgoExpirationDate expirations = constraint.getAlgoExpirationDate();
		if (expirations != null && Utils.isCollectionNotEmpty(expirations.getAlgo())) {
			SimpleDateFormat dateFormat = new SimpleDateFormat(Utils.isStringEmpty(expirations.getFormat()) ? DEFAULT_DATE_FORMAT : expirations.getFormat());
			for (Algo algo : expirations.getAlgo()) {
				String currentAlgo = algo.getValue();
				String expirationDate = algo.getDate();
				try {
					result.put(currentAlgo, dateFormat.parse(expirationDate));
				} catch (ParseException e) {
					LOG.warn("Unable to parse '{}' with format '{}'", expirationDate, dateFormat);
				}
			}
		}
		return result;
	}

	private List<String> extract(ListAlgo listAlgo) {
		List<String> result = new ArrayList<String>();
		if (listAlgo != null && Utils.isCollectionNotEmpty(listAlgo.getAlgo())) {
			for (Algo algo : listAlgo.getAlgo()) {
				result.add(algo.getValue());
			}
		}
		return result;
	}

}
