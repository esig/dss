package eu.europa.esig.dss.tsl.function.converter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.tsl.InternationalNamesType;
import eu.europa.esig.trustedlist.jaxb.tsl.MultiLangNormStringType;

public class InternationalNamesTypeConverter implements Function<InternationalNamesType, Map<String, List<String>>> {

	@Override
	public Map<String, List<String>> apply(InternationalNamesType original) {
		Map<String, List<String>> result = new HashMap<String, List<String>>();
		if (original != null && Utils.isCollectionNotEmpty(original.getName())) {
			for (MultiLangNormStringType multiLangNormString : original.getName()) {
				final String lang = multiLangNormString.getLang();
				final String value = multiLangNormString.getValue();
				List<String> resultsByLang = result.get(lang);
				if (resultsByLang == null) {
					resultsByLang = new ArrayList<String>();
					result.put(lang, resultsByLang);
				}
				resultsByLang.add(value);
			}
		}
		return result;
	}

}
