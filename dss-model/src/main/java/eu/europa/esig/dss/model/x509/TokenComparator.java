package eu.europa.esig.dss.model.x509;

import java.io.Serializable;
import java.util.Comparator;

public class TokenComparator implements Comparator<Token>, Serializable {

	private static final long serialVersionUID = -6552184098542873764L;

	@Override
	public int compare(Token o1, Token o2) {
		return o1.getDSSIdAsString().compareTo(o2.getDSSIdAsString());
	}

}
